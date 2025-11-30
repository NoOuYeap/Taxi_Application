// serverV8.js — 로그인 + 경로 매칭 + 자동 채팅방 (Express + MongoDB + Socket.IO)
// ----------------------------------------------------------------------------
// 흐름 요약
// 1) /api/v7/signup, /api/v7/login 으로 사용자 계정을 간단히 관리(메모리 저장)
// 1-1) 회원가입 정보: 이름,주민번호 앞자리, 성별, 지역, 전화번호
// 1-2) 회원가입 이후, 내정보 확인 가능, 비밀번호 변경가능 
// 2) 로그인한 사용자는 matchId를 선택해 출발지/도착지를 제출(/api/v7/submit)
// 3) 두 사용자가 모두 입력하면 TMAP 경로를 조회해 유사도를 계산(기본 60% 이상이면 성공)
// 4) 매칭 성공 시 해당 matchId로 채팅방을 자동 생성하고, 상태 스트림(/api/v7/stream)을 통해 알림
// 5) Socket.IO 를 이용해 matchId 방에서 실시간 채팅
//    (클라이언트는 로그인 토큰 + matchId로 joinRoom 이벤트 호출)
// ----------------------------------------------------------------------------

const fs = require("fs");
const path = require("path");
const http = require("http");
const crypto = require("crypto");
const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const bodyParser = require("body-parser");
const { MongoClient } = require("mongodb");
const { Server } = require("socket.io");
const argon2 = require("argon2");
dotenv.config();

// ---------------------- 설정 로더 ----------------------
function num(v, fallback) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}
function loadJsonSafe(p) {
  try { return JSON.parse(fs.readFileSync(p, "utf-8")); } catch { return {}; }
}
function loadConfig() {
  const defaults = {
    port: 3000,
    similarity: {
      recommendCutoff: 0.60,
      endpointsMin: 0.60,
      pickupMaxKm: 1.5,
      dropMaxKm: 1.5,
      clampKm: 3,
      resampleMaxPoints: 100,
      weights: { path: 0.8, endpoints: 0.2 }
    }
  };

  const cfgPath = path.join(__dirname, "config", "app.config.json");
  const fileCfg = loadJsonSafe(cfgPath);

  const merged = {
    ...defaults,
    ...fileCfg,
    similarity: {
      ...defaults.similarity,
      ...(fileCfg.similarity || {}),
      weights: {
        ...defaults.similarity.weights,
        ...((fileCfg.similarity && fileCfg.similarity.weights) || {})
      }
    }
  };

  const env = process.env;
  return {
    port: num(env.PORT, merged.port),
    tmapApiKey: env.TMAP_API_KEY || "",
    mongoUri: env.MONGODB_URI || "",
    mongoDb: env.MONGODB_DB || "tmap",
    mongoCol: env.MONGODB_COLLECTION || "matches",
    usersCol: env.MONGODB_USERS_COLLECTION || "users",
    couponsCol: env.MONGODB_COUPONS_COLLECTION || "coupons",
    couponsCol: env.MONGODB_COUPONS_COLLECTION || "coupons",
    similarity: {
      recommendCutoff: num(env.SIM_RECOMMEND_CUTOFF, merged.similarity.recommendCutoff),
      endpointsMin:    num(env.SIM_ENDPOINTS_MIN,    merged.similarity.endpointsMin),
      pickupMaxKm:     num(env.SIM_PICKUP_MAX_KM,    merged.similarity.pickupMaxKm),
      dropMaxKm:       num(env.SIM_DROP_MAX_KM,      merged.similarity.dropMaxKm),
      clampKm:         num(env.SIM_PATH_CLAMP_KM,    merged.similarity.clampKm),
      resampleMaxPoints: Math.max(10, Math.floor(num(env.SIM_RESAMPLE_MAX_POINTS, merged.similarity.resampleMaxPoints))),
      weights: {
        path:       num(env.SIM_PATH_WEIGHT,       merged.similarity.weights.path),
        endpoints:  num(env.SIM_ENDPOINTS_WEIGHT,  merged.similarity.weights.endpoints)
      }
    }
  };
}

const CFG = loadConfig();
const APP_KEY = CFG.tmapApiKey;
const PORT = CFG.port;
const HASH_SECRET = process.env.HASH_SECRET || "change-this-secret"; // 환경마다 다르게 설정해야 하는 해시 시드

// 비밀번호 외의 민감 정보(전화번호, 주민번호 앞자리 등)를 안전하게 비교하기 위한 결정적 해시
function hashSensitive(value) {
  return crypto.createHash("sha256").update(`${String(value)}|${HASH_SECRET}`).digest("hex");
}

// ---------------------- 앱/서버/Socket.IO 초기화 ----------------------
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*", methods: ["GET", "POST"] } });

app.use(cors());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

// ---------------------- MongoDB 연결 ----------------------
let mongoClient;
let matchesCol;
let usersCol;
let couponsCol;

async function initMongo() {
  if (!CFG.mongoUri) throw new Error("MONGODB_URI가 .env에 없습니다.");
  mongoClient = new MongoClient(CFG.mongoUri, {});
  await mongoClient.connect();
  const db = mongoClient.db(CFG.mongoDb);
  matchesCol = db.collection(CFG.mongoCol);
  usersCol = db.collection(CFG.usersCol);
  couponsCol = db.collection(CFG.couponsCol);
  await matchesCol.createIndex({ matchId: 1 }, { unique: true });
  await usersCol.createIndex({ phone: 1 }, { unique: true, sparse: true });
  await usersCol.createIndex({ username: 1 }, { unique: true });
  await couponsCol.createIndex({ code: 1 }, { unique: true });
}

// ---------------------- 로그인 토큰(간단 구현) ----------------------
const tokenStore = new Map(); // token -> session info

function createToken(username, role = "user") {
  const token = `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  tokenStore.set(token, { username, role, issuedAt: Date.now() });
  return token;
}

function getUserFromToken(req) {
  const auth = req.headers.authorization;
  if (!auth) return null;
  const [, token] = auth.split(" ");
  if (!token) return null;
  const entry = tokenStore.get(token);
  if (!entry) return null;
  return { token, username: entry.username, role: entry.role || "user" };
}

function authRequired(req, res, next) {
  const info = getUserFromToken(req);
  if (!info) return res.status(401).json({ ok: false, error: "인증 필요" });
  req.user = info;
  next();
}

function adminRequired(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ ok: false, error: "관리자 권한이 필요합니다." });
  }
  next();
}

// ---------------------- 지오코딩/유사도 유틸 ----------------------
function parseLatLng(text) {
  const m = String(text).trim().match(/^\s*([+-]?\d+(?:\.\d+)?)\s*,\s*([+-]?\d+(?:\.\d+)?)\s*$/);
  if (!m) return null;
  const lat = parseFloat(m[1]); const lng = parseFloat(m[2]);
  return (Number.isFinite(lat) && Number.isFinite(lng)) ? { lat, lng } : null;
}

async function geocodeFullText(query) {
  const url = new URL("https://apis.openapi.sk.com/tmap/geo/fullAddrGeo");
  url.searchParams.set("fullAddr", query);
  url.searchParams.set("format", "json");

  const resp = await fetch(url, { headers: { appKey: APP_KEY } });
  if (!resp.ok) throw new Error(`Geocoding failed: ${resp.status} ${resp.statusText}`);

  const data = await resp.json();
  const c = data?.coordinateInfo?.coordinate?.[0] || data?.coordinate?.[0] || data?.addressInfo || null;

  const lat = parseFloat(c?.lat ?? c?.newLat ?? c?.noorLat ?? c?.latY);
  const lng = parseFloat(c?.lon ?? c?.newLon ?? c?.noorLon ?? c?.lonX);
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
    throw new Error("지오코딩 결과가 올바르지 않습니다.");
  }
  return { lat, lng };
}

async function toCoords(input) {
  return parseLatLng(input) ?? await geocodeFullText(input);
}

async function getCarRoute({ start, end }) {
  const url = "https://apis.openapi.sk.com/tmap/routes";
  const body = {
    startX: start.lng, startY: start.lat,
    endX: end.lng,     endY: end.lat,
    reqCoordType: "WGS84GEO",
    resCoordType: "WGS84GEO"
  };
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", appKey: APP_KEY },
    body: JSON.stringify(body)
  });
  if (!resp.ok) {
    const t = await resp.text();
    throw new Error(`Route failed: ${resp.status} ${resp.statusText} - ${t}`);
  }
  return await resp.json();
}

function extractPathLatLng(routeJson) {
  const coords = [];
  const feats = Array.isArray(routeJson?.features) ? routeJson.features : [];
  for (const f of feats) {
    const g = f?.geometry;
    if (!g) continue;
    if (g.type === "LineString" && Array.isArray(g.coordinates)) {
      for (const [lng, lat] of g.coordinates) {
        if (Number.isFinite(lat) && Number.isFinite(lng)) coords.push({ lat, lng });
      }
    } else if (g.type === "MultiLineString" && Array.isArray(g.coordinates)) {
      for (const line of g.coordinates) {
        for (const [lng, lat] of line) {
          if (Number.isFinite(lat) && Number.isFinite(lng)) coords.push({ lat, lng });
        }
      }
    }
  }
  return coords;
}

function haversineKm(a, b) {
  const toRad = d => d * Math.PI / 180;
  const R = 6371;
  const dLat = toRad(b.lat - a.lat);
  const dLng = toRad(b.lng - a.lng);
  const s = Math.sin(dLat/2)**2 +
            Math.cos(toRad(a.lat)) * Math.cos(toRad(b.lat)) *
            Math.sin(dLng/2)**2;
  return 2 * R * Math.asin(Math.sqrt(s));
}

function resamplePath(points, maxPoints) {
  if (!Array.isArray(points) || points.length <= maxPoints) return points || [];
  const out = [];
  const step = (points.length - 1) / (maxPoints - 1);
  for (let i = 0; i < maxPoints; i++) {
    const idx = i * step;
    const low = Math.floor(idx);
    const high = Math.min(points.length - 1, Math.ceil(idx));
    const t = idx - low;
    if (low === high) out.push(points[low]);
    else {
      const p = points[low], q = points[high];
      out.push({ lat: p.lat + (q.lat - p.lat) * t, lng: p.lng + (q.lng - p.lng) * t });
    }
  }
  return out;
}

function discreteFrechet(A, B, metricFn) {
  if (!A.length || !B.length) return Infinity;
  const ca = Array.from({ length: A.length }, () => Array(B.length).fill(-1));
  function c(i, j) {
    if (ca[i][j] > -1) return ca[i][j];
    const d = metricFn(A[i], B[j]);
    if (i === 0 && j === 0) ca[i][j] = d;
    else if (i === 0)       ca[i][j] = Math.max(c(i, j-1), d);
    else if (j === 0)       ca[i][j] = Math.max(c(i-1, j), d);
    else                    ca[i][j] = Math.max(Math.min(c(i-1, j), c(i-1, j-1), c(i, j-1)), d);
    return ca[i][j];
  }
  return c(A.length - 1, B.length - 1);
}

function pathSimilarityScore(pathA, pathB, clampKm, maxPts) {
  const A = resamplePath(pathA, maxPts);
  const B = resamplePath(pathB, maxPts);
  if (A.length < 2 || B.length < 2) return 0;
  const dKm = discreteFrechet(A, B, haversineKm);
  const score = 1 - Math.min(dKm, clampKm) / clampKm;
  return Math.max(0, Math.min(1, score));
}

function proximityScore(distanceKm, thresholdKm) {
  if (distanceKm <= 0) return 1;
  return Math.max(0, Math.min(1, 1 - (distanceKm / thresholdKm)));
}
function endpointsSimilarityScore(origA, destA, origB, destB, thresholdKm) {
  const sStart = proximityScore(haversineKm(origA, origB), thresholdKm);
  const sEnd   = proximityScore(haversineKm(destA, destB), thresholdKm);
  return 0.5 * sStart + 0.5 * sEnd;
}

function combinedSimilarity(pathA, pathB, oA, dA, oB, dB, cfg) {
  const { clampKm, resampleMaxPoints, weights } = cfg.similarity;
  const pathSim = pathSimilarityScore(pathA, pathB, clampKm, resampleMaxPoints);
  const endpointsSim = endpointsSimilarityScore(oA, dA, oB, dB, cfg.similarity.clampKm);
  const score = weights.path * pathSim + weights.endpoints * endpointsSim;
  return { score, breakdown: { pathSim, endpointsSim, weights } };
}

// ---------------------- SSE 관리 ----------------------
const sseClients = new Map(); // key: matchId:caseId -> Set(res)
const sseKey = (matchId, caseId) => `${matchId}:${caseId || ""}`;

function addSseClient(matchId, caseId, res) {
  const key = sseKey(matchId, caseId);
  if (!sseClients.has(key)) sseClients.set(key, new Set());
  sseClients.get(key).add(res);
}
function removeSseClient(matchId, caseId, res) {
  const key = sseKey(matchId, caseId);
  const set = sseClients.get(key);
  if (set) {
    set.delete(res);
    if (set.size === 0) sseClients.delete(key);
  }
}
function sendSse(matchId, caseId, event, data) {
  const key = sseKey(matchId, caseId);
  const set = sseClients.get(key);
  if (!set) return;
  const payload = `event: ${event}\n` + `data: ${JSON.stringify(data)}\n\n`;
  for (const res of set) {
    try { res.write(payload); } catch {}
  }
}

function statusPayload(doc, caseId) {
  if (!doc) return { status: "waiting", label: "매칭 대기중", caseId: null };
  const cases = Array.isArray(doc.cases) ? doc.cases : [];
  const c = cases.find((k) => k.caseId === caseId) || cases[cases.length - 1] || {};
  const status = c.status || "waiting";
  const labelMap = { waiting: "매칭 대기중", matched: "매칭성공", failed: "매칭실패", archived: "종료" };
  return {
    status,
    label: labelMap[status] || status,
    score: c?.score ?? null,
    percent: c?.percent ?? (c?.score != null ? Math.round(c.score * 100) : null),
    note: c?.note || null,
    chatRoomId: c?.chatRoomId || null,
    caseId: c?.caseId || null
  };
}

function closeSseStream(matchId, caseId) {
  const key = sseKey(matchId, caseId);
  const set = sseClients.get(key);
  if (!set) return;
  for (const res of set) {
    try { res.write("event: closed\ndata: {}\n\n"); res.end?.(); } catch {}
  }
  sseClients.delete(key);
}

app.get("/api/v7/stream", async (req, res) => {
  const matchId = String(req.query.matchId || "").trim();
  const caseId = String(req.query.caseId || "").trim();
  if (!matchId || !caseId) return res.status(400).end("matchId and caseId required");

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  addSseClient(matchId, caseId, res);

  try {
    const doc = await matchesCol.findOne({ matchId });
    res.write(`event: status\n` + `data: ${JSON.stringify(statusPayload(doc, caseId))}\n\n`);
  } catch {}

  const keep = setInterval(() => {
    try { res.write(": keep-alive\n\n"); } catch {}
  }, 25000);

  req.on("close", () => {
    clearInterval(keep);
    removeSseClient(matchId, caseId, res);
  });
});

// ---------------------- 계정/인증 API ----------------------
app.post("/api/v7/signup", async (req, res) => {
  try {
    const { username, password, name, ssnFront, gender, region, phone } = req.body || {};
    const missing = [];
    if (!username) missing.push("username");
    if (!password) missing.push("password");
    if (!name) missing.push("name");
    if (!ssnFront) missing.push("ssnFront");
    if (!gender) missing.push("gender");
    if (!region) missing.push("region");
    if (!phone) missing.push("phone");
    if (missing.length) {
      return res.status(400).json({ ok: false, error: `${missing.join(', ')} required` });
    }

    const normalized = {
      username: String(username).trim(),
      password: String(password),
      name: String(name).trim(),
      ssnFront: String(ssnFront).replace(/\D/g, '').slice(0, 6),
      gender: String(gender).toLowerCase(),
      region: String(region).trim(),
      phone: String(phone).replace(/[^0-9]/g, '')
    };

    if (normalized.username.length < 4 || normalized.username.length > 32) {
      return res.status(400).json({ ok: false, error: 'username must be 4-32 chars.' });
    }
    if (!/^[a-zA-Z0-9._-]+$/.test(normalized.username)) {
      return res.status(400).json({ ok: false, error: 'username can contain letters, numbers, dot, underscore, hyphen.' });
    }
    if (normalized.password.length < 6) {
      return res.status(400).json({ ok: false, error: 'password must be at least 6 chars.' });
    }
    if (normalized.ssnFront.length !== 6) {
      return res.status(400).json({ ok: false, error: 'ssnFront must be 6 digits.' });
    }
    if (!['male', 'female'].includes(normalized.gender)) {
      return res.status(400).json({ ok: false, error: 'gender must be male or female.' });
    }
    if (!normalized.region) {
      return res.status(400).json({ ok: false, error: 'region is required.' });
    }
    if (normalized.phone.length < 10 || normalized.phone.length > 11) {
      return res.status(400).json({ ok: false, error: 'phone must be 10-11 digits.' });
    }

    const phoneHash = hashSensitive(normalized.phone); // 원본을 저장하지 않고도 중복 여부를 확인하기 위한 해시값
    const [usernameDoc, phoneDoc] = await Promise.all([
      usersCol.findOne({ username: normalized.username }),
      usersCol.findOne({ phone: phoneHash })
    ]);
    if (usernameDoc) {
      return res.status(409).json({ ok: false, error: "username already registered." });
    }
    if (phoneDoc) {
      return res.status(409).json({ ok: false, error: "phone already registered." });
    }

    const doc = {
      username: normalized.username,
      password: await argon2.hash(normalized.password), // Argon2로 비밀번호를 단방향 암호화
      name: normalized.name,
      ssnFront: hashSensitive(normalized.ssnFront),
      gender: hashSensitive(normalized.gender),
      region: normalized.region,
      phone: phoneHash,
      usageCount: 0, // 신규 가입자는 사용 횟수를 0으로 시작
      createdAt: new Date(),
      role: "user"
    };

    await usersCol.insertOne(doc);
    res.status(201).json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

app.post("/api/v7/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ ok: false, error: "username/password 필요" });
    }

    const normalizedUsername = String(username).trim();
    const user = await usersCol.findOne({ username: normalizedUsername });
    if (!user) return res.status(401).json({ ok: false, error: "로그인 실패" });

    const passwordOk = await argon2.verify(user.password, String(password)); // 입력 비밀번호를 기존 해시와 비교
    if (!passwordOk) return res.status(401).json({ ok: false, error: "로그인 실패" });

    const role = typeof user.role === "string" ? user.role : "user";
    const token = createToken(normalizedUsername, role);
    res.json({ ok: true, token, username: normalizedUsername, role, isAdmin: role === "admin" });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

app.post("/api/v7/logout", authRequired, (req, res) => {
  tokenStore.delete(req.user.token);
  res.json({ ok: true });
});

app.get("/api/v7/me", authRequired, async (req, res) => {
  try {
    const user = await usersCol.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ ok: false, error: "사용자를 찾을 수 없습니다." });

    res.json({
      ok: true,
      username: user.username,
      name: user.name,
      usageCount: user.usageCount || 0,
      role: user.role || "user",
      isAdmin: user.role === "admin"
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

// ---------------------- 비밀번호 변경 API ----------------------
app.post("/api/v7/password", authRequired, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ ok: false, error: "현재/새 비밀번호를 모두 입력하세요." });
    }
    if (String(newPassword).length < 6) {
      return res.status(400).json({ ok: false, error: "새 비밀번호는 6자 이상이어야 합니다." });
    }

    const user = await usersCol.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ ok: false, error: "사용자를 찾을 수 없습니다." });

    const verified = await argon2.verify(user.password, String(currentPassword));
    if (!verified) return res.status(401).json({ ok: false, error: "현재 비밀번호가 일치하지 않습니다." });

    const hashed = await argon2.hash(String(newPassword));
    await usersCol.updateOne(
      { _id: user._id },
      { $set: { password: hashed, passwordUpdatedAt: new Date() } }
    );

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});



app.post("/api/v7/coupons/apply", authRequired, async (req, res) => {
  try {
    const raw = (req.body?.code ?? "").toString().trim();
    if (!raw) {
      return res.status(400).json({ ok: false, error: "쿠폰 코드를 입력해 주세요." });
    }
    const normalized = raw.toUpperCase();
    const username = req.user.username;
    const user = await usersCol.findOne({ username });
    if (!user) {
      return res.status(404).json({ ok: false, error: "사용자를 찾을 수 없습니다." });
    }

    const couponDoc =
      (await couponsCol.findOne({ code: normalized })) ||
      (await couponsCol.findOne({ code: raw }));
    if (!couponDoc) {
      return res.status(404).json({ ok: false, error: "유효하지 않은 쿠폰 코드입니다." });
    }

    const now = new Date();
    if (couponDoc.expiresAt && new Date(couponDoc.expiresAt) < now) {
      return res.status(400).json({ ok: false, error: "기간이 만료된 쿠폰입니다." });
    }

    const usedUsers = Array.isArray(couponDoc.usedUsers) ? couponDoc.usedUsers : [];
    if (usedUsers.includes(username)) {
      return res.status(409).json({ ok: false, error: "이미 사용한 쿠폰 코드입니다." });
    }
    if (couponDoc.maxUses && usedUsers.length >= couponDoc.maxUses) {
      return res.status(409).json({ ok: false, error: "해당 쿠폰은 더 이상 사용할 수 없습니다." });
    }

    const storedCode = couponDoc.code?.toString().trim() || normalized;
    if (Array.isArray(user.coupons) && user.coupons.some((c) => c.code === storedCode)) {
      return res.status(409).json({ ok: false, error: "이미 보유 중인 쿠폰입니다." });
    }

    const discountType = couponDoc.discountType || "percent";
    const discountValue =
      typeof couponDoc.discountValue === "number" ? couponDoc.discountValue : 10;
    const safeDiscount =
      discountType === "percent"
        ? Math.min(100, Math.max(1, discountValue))
        : Math.max(0, discountValue);

    const userCoupon = {
      code: storedCode,
      discountType,
      discountValue: safeDiscount,
      description:
        couponDoc.description ||
        (discountType === "percent"
          ? `${safeDiscount}% 할인 쿠폰`
          : `${safeDiscount.toLocaleString()}원 할인 쿠폰`),
      issuedAt: now,
    };

    const updateUser = await usersCol.updateOne(
      { username },
      { $push: { coupons: userCoupon } },
    );
    if (!updateUser.matchedCount) {
      return res.status(404).json({ ok: false, error: "사용자 정보를 갱신할 수 없습니다." });
    }

    await couponsCol.updateOne(
      { _id: couponDoc._id },
      {
        $addToSet: { usedUsers: username },
        $inc: { usedCount: 1 },
        $set: { lastUsedAt: now },
      },
    );

    res.json({ ok: true, coupon: userCoupon });
  } catch (err) {
    console.error("apply coupon error", err);
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});
// ---------------------- 관리자 통계 API ----------------------
app.get("/api/v10/admin/stats", authRequired, adminRequired, async (req, res) => {
  try {
    const now = new Date();
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const dayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const progressStatuses = ["waiting", "pending", "processing"];

    const [todayMatched, inProgress, failedLast24h, couponsAggregation, matchStatusCounts, couponTypes] = await Promise.all([
      matchesCol.countDocuments({ status: "matched", updatedAt: { $gte: startOfToday } }),
      matchesCol.countDocuments({ status: { $in: progressStatuses } }),
      matchesCol.countDocuments({ status: "failed", updatedAt: { $gte: dayAgo } }),
      usersCol
        .aggregate([
          { $project: { couponCount: { $size: { $ifNull: ["$coupons", []] } } } },
          { $group: { _id: null, total: { $sum: "$couponCount" } } }
        ])
        .toArray(),
      matchesCol
        .aggregate([
          {
            $match: {
              status: { $in: ["matched", "failed"] },
              updatedAt: { $gte: startOfToday }
            }
          },
          { $group: { _id: "$status", count: { $sum: 1 } } }
        ])
        .toArray(),
      couponsCol.countDocuments({})
    ]);

    const couponsIssued = couponsAggregation[0]?.total || 0;
    const matchedCount = matchStatusCounts.find((doc) => doc._id === "matched")?.count || 0;
    const failedCount = matchStatusCounts.find((doc) => doc._id === "failed")?.count || 0;
    const totalMatchEvaluated = matchedCount + failedCount;
    const successRate = totalMatchEvaluated > 0 ? matchedCount / totalMatchEvaluated : null;

    res.json({
      ok: true,
      stats: {
        todayMatched,
        inProgress,
        failedLast24h,
        couponsIssued,
        couponTypes,
        matchedCount,
        failedCount,
        totalEvaluated: totalMatchEvaluated,
        successRate
      }
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

app.get("/api/v10/admin/recent", authRequired, adminRequired, async (req, res) => {
  try {
    const [recentMatches, recentUsers] = await Promise.all([
      matchesCol
        .find(
          {},
          { projection: { matchId: 1, status: 1, percent: 1, updatedAt: 1, note: 1, users: 1, createdAt: 1 } }
        )
        .sort({ updatedAt: -1 })
        .limit(10)
        .toArray(),
      usersCol
        .find({}, { projection: { username: 1, name: 1, region: 1, usageCount: 1, coupons: 1, createdAt: 1 } })
        .sort({ createdAt: -1 })
        .limit(10)
        .toArray()
    ]);

    const formattedMatches = recentMatches.map((doc) => ({
      matchId: doc.matchId,
      status: doc.status || "waiting",
      percent: doc.percent ?? null,
      updatedAt: doc.updatedAt || doc.createdAt || null,
      note: doc.note || null,
      users: Object.keys(doc.users || {})
    }));

    const formattedUsers = recentUsers.map((doc) => ({
      username: doc.username,
      name: doc.name,
      region: doc.region || null,
      createdAt: doc.createdAt || null,
      usageCount: doc.usageCount || 0,
      couponCount: Array.isArray(doc.coupons) ? doc.coupons.length : 0
    }));

    res.json({ ok: true, matches: formattedMatches, users: formattedUsers });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

// ---------------------- 관리자 월별 집계 API ----------------------
app.get("/api/v10/admin/monthly-signups", authRequired, adminRequired, async (req, res) => {
  try {
    const now = new Date();
    const parsedYear = Number.parseInt(String(req.query.year || ""), 10);
    const year = Number.isFinite(parsedYear) ? parsedYear : now.getFullYear();
    if (year < 2000 || year > 2100) {
      return res.status(400).json({ ok: false, error: "year 파라미터는 2000~2100 사이여야 합니다." });
    }

    const start = new Date(year, 0, 1);
    const end = new Date(year + 1, 0, 1);

    const aggregation = await usersCol
      .aggregate([
        { $match: { createdAt: { $gte: start, $lt: end } } },
        {
          $group: {
            _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } },
            count: { $sum: 1 }
          }
        },
        { $sort: { "_id": 1 } }
      ])
      .toArray();

    const monthMap = new Map(aggregation.map((doc) => [doc._id, doc.count]));
    const months = [];
    for (let m = 0; m < 12; m++) {
      const label = `${year}-${String(m + 1).padStart(2, "0")}`;
      months.push({ month: label, count: monthMap.get(label) || 0 });
    }

    res.json({ ok: true, year, months });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

// ---------------------- 매칭/유사도 API (case 기반) ----------------------
app.post("/api/v7/match/cleanup", authRequired, async (req, res) => {
  try {
    const { matchId, caseId, force } = req.body || {};
    if (!matchId || !caseId) {
      return res.status(400).json({ ok: false, error: "matchId, caseId required" });
    }

    const doc = await matchesCol.findOne({ matchId });
    if (!doc) return res.status(404).json({ ok: false, error: "match not found" });

    const cases = Array.isArray(doc.cases) ? doc.cases : [];
    const idx = cases.findIndex((c) => c.caseId === caseId);
    if (idx === -1) return res.status(404).json({ ok: false, error: "case not found" });
    const c = cases[idx];
    const participants = Object.keys(c.users || {});
    const others = participants.filter((user) => user !== req.user.username);
    if (others.length > 0 && !force) {
      return res.status(409).json({ ok: false, error: "다른 사용자가 아직 남아 있습니다." });
    }


    cases[idx] = {
      ...c,
      status: "archived",
      archived: true,
      archivedAt: new Date(),
      chatRoomId: null,
      updatedAt: new Date()
    };
    // 최상위 상태도 종료로 반영
    await matchesCol.updateOne(
      { matchId },
      { $set: { cases, updatedAt: new Date() } }
    );
    cleanupMatchResources(matchId, caseId, c.chatRoomId);
    res.json({ ok: true, archived: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

app.post("/api/v7/submit", authRequired, async (req, res) => {
  try {
    const { matchId, origin, destination } = req.body || {};
    if (!matchId || !origin || !destination) {
      return res.status(400).json({ ok: false, error: "matchId, origin, destination required" });
    }

    const username = req.user.username;
    await usersCol.updateOne({ username }, { $inc: { usageCount: 1 } });
    const now = new Date();
    const doc = await matchesCol.findOne({ matchId });

    const cases = Array.isArray(doc?.cases) ? doc.cases : [];
    let target = cases.find(
      (c) =>
        !c.archived &&
        c.status !== "archived" &&
        c.status !== "matched" &&
        c.status !== "failed" &&
        Object.keys(c.users || {}).length < 2
    );
    if (!target) {
      target = {
        caseId: `case-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        status: "waiting",
        users: {},
        createdAt: now,
        updatedAt: now,
        chatRoomId: null
      };
      cases.push(target);
    }

    target.users = target.users || {};
    target.users[username] = { username, origin, destination, submittedAt: now };
    target.updatedAt = now;
    target.status = target.status || "waiting";

    await matchesCol.updateOne(
      { matchId },
      {
        $setOnInsert: { matchId, createdAt: now },
        $set: { cases, status: target.status, updatedAt: now }
      },
      { upsert: true }
    );

    const updated = await matchesCol.findOne({ matchId });
    const current = (updated.cases || []).find((c) => c.caseId === target.caseId) || target;
    res.json({ ok: true, caseId: current.caseId, status: statusPayload(updated, current.caseId) });

    checkAndMatch(matchId, current.caseId).catch(() => {});
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

app.get("/api/v7/status", authRequired, async (req, res) => {
  try {
    const matchId = String(req.query.matchId || "").trim();
    const caseId = String(req.query.caseId || "").trim();
    if (!matchId || !caseId) return res.status(400).json({ ok: false, error: "matchId, caseId required" });
    const doc = await matchesCol.findOne({ matchId });
    res.json({ ok: true, status: statusPayload(doc, caseId) });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

app.post("/api/v7/reset", authRequired, async (req, res) => {
  try {
    const { matchId, caseId } = req.body || {};
    if (!matchId || !caseId) return res.status(400).json({ ok: false, error: "matchId, caseId required" });
    const doc = await matchesCol.findOne({ matchId });
    if (!doc) return res.status(404).json({ ok: false, error: "match not found" });
    const cases = Array.isArray(doc.cases) ? doc.cases : [];
    const idx = cases.findIndex((c) => c.caseId === caseId);
    if (idx === -1) return res.status(404).json({ ok: false, error: "case not found" });

    cases[idx] = {
      ...cases[idx],
      status: "waiting",
      score: null,
      percent: null,
      breakdown: null,
      note: "초기화되었습니다.",
      chatRoomId: null,
      users: {},
      updatedAt: new Date()
    };
    await matchesCol.updateOne(
      { matchId },
      { $set: { cases, status: "waiting", updatedAt: new Date() }, $unset: { error: "" } },
      { upsert: true }
    );
    sendSse(matchId, caseId, "status", statusPayload(await matchesCol.findOne({ matchId }), caseId));
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

// ---------------------- 매칭 처리 & 채팅방 생성 ----------------------
async function computeSimilarity(matchDoc, caseId) {
  const cases = Array.isArray(matchDoc?.cases) ? matchDoc.cases : [];
  const c = cases.find((k) => k.caseId === caseId);
  if (!c) return { ready: false };
  const users = c.users || {};
  const usernames = Object.keys(users);
  if (usernames.length < 2) return { ready: false };

  const [A, B] = usernames;
  const uA = users[A];
  const uB = users[B];
  if (!uA?.origin || !uA?.destination || !uB?.origin || !uB?.destination) {
    return { ready: false };
  }

  if (!APP_KEY) throw new Error("TMAP_API_KEY가 .env에 없습니다.");

  const [oA, dA, oB, dB] = await Promise.all([
    toCoords(uA.origin), toCoords(uA.destination),
    toCoords(uB.origin), toCoords(uB.destination)
  ]);

  const [rA, rB] = await Promise.all([
    getCarRoute({ start: oA, end: dA }),
    getCarRoute({ start: oB, end: dB })
  ]);

  const pathA = extractPathLatLng(rA);
  const pathB = extractPathLatLng(rB);
  if (pathA.length < 2 || pathB.length < 2) {
    return { ready: true, score: 0, percent: 0, details: { pathSim: 0, endpointsSim: 0 }, note: "경로 좌표가 부족합니다." };
  }

  const sim = combinedSimilarity(pathA, pathB, oA, dA, oB, dB, CFG);
  const percent = Math.round(sim.score * 100);
  return { ready: true, score: sim.score, percent, details: sim.breakdown };
}

const chatRooms = new Map(); // roomId -> { members: Map<socketId,{username}>, history: [] }
const HISTORY_LIMIT = 200;

function ensureChatRoom(roomId) {
  if (!chatRooms.has(roomId)) {
    chatRooms.set(roomId, { members: new Map(), history: [] });
  }
  return chatRooms.get(roomId);
}

function cleanupMatchResources(matchId, caseId, chatRoomId) {
  const roomId = chatRoomId || `chat-${matchId}-${caseId || ""}`;
  const room = chatRooms.get(roomId);
  if (room) {
    for (const socketId of Array.from(room.members.keys())) {
      const socket = io.sockets.sockets.get(socketId);
      if (socket) {
        socket.leave(roomId);
        socket.data.roomId = null;
      }
    }
    chatRooms.delete(roomId);
  }
  closeSseStream(matchId, caseId);
}

async function checkAndMatch(matchId, caseId) {
  const doc = await matchesCol.findOne({ matchId });
  if (!doc) return;
  const cases = Array.isArray(doc.cases) ? doc.cases : [];
  const idx = cases.findIndex((c) => c.caseId === caseId);
  if (idx === -1) return;
  const c = cases[idx];
  if (c.archived || c.status === "archived" || c.status === "matched" || c.status === "failed") return;

  try {
    const result = await computeSimilarity(doc, caseId);
    if (!result.ready) {
      cases[idx].status = "waiting";
      cases[idx].note = "다른 사용자를 기다리는 중입니다.";
      cases[idx].updatedAt = new Date();
      await matchesCol.updateOne({ matchId }, { $set: { cases, status: cases[idx].status, updatedAt: new Date() } });
      sendSse(matchId, caseId, "status", statusPayload(await matchesCol.findOne({ matchId }), caseId));
      return;
    }

    const success = result.percent >= Math.round(CFG.similarity.recommendCutoff * 100);
    const status = success ? "matched" : "failed";
    const note = success ? "매칭이 완료되었습니다." : "유사도가 기준치 미만입니다.";
    const chatRoomId = success ? `chat-${matchId}-${caseId}` : null;

    cases[idx] = {
      ...cases[idx],
      status,
      score: result.score,
      percent: result.percent,
      breakdown: result.details,
      note,
      chatRoomId,
      updatedAt: new Date()
    };

    await matchesCol.updateOne(
      { matchId },
      { $set: { cases, status, percent: result.percent, updatedAt: new Date() } }
    );

    if (success) ensureChatRoom(chatRoomId);

    sendSse(matchId, caseId, "status", statusPayload(await matchesCol.findOne({ matchId }), caseId));
  } catch (err) {
    cases[idx] = {
      ...cases[idx],
      status: "failed",
      error: String(err.message || err),
      updatedAt: new Date()
    };
    await matchesCol.updateOne({ matchId }, { $set: { cases, status: "failed", updatedAt: new Date() } });
    sendSse(matchId, caseId, "status", statusPayload(await matchesCol.findOne({ matchId }), caseId));
  }
}

// ---------------------- Socket.IO (채팅) ----------------------
io.on("connection", (socket) => {
  console.log("socket connected", socket.id);

  socket.on("joinRoom", async ({ token, matchId, caseId }) => {
    try {
      const entry = tokenStore.get(token);
      if (!entry) return socket.emit("error", { message: "인증 실패" });
      const username = entry.username;
      const doc = await matchesCol.findOne({ matchId });
      const cases = Array.isArray(doc?.cases) ? doc.cases : [];
      const c = cases.find((k) => k.caseId === caseId);
      if (!doc || !c || c.status !== "matched" || c.chatRoomId !== `chat-${matchId}-${caseId}`) {
        return socket.emit("error", { message: "매칭이 완료되지 않았습니다." });
      }

      const roomId = c.chatRoomId;
      const room = ensureChatRoom(roomId);

      socket.data.username = username;
      socket.data.roomId = roomId;
      socket.join(roomId);
      room.members.set(socket.id, { username });

      socket.emit("history", room.history);
      io.to(roomId).emit("systemMessage", { type: "join", text: `${username} 님이 입장했습니다.`, ts: Date.now() });
      io.to(roomId).emit("roomUsers", Array.from(room.members.values()).map(v => v.username));
    } catch (err) {
      socket.emit("error", { message: String(err.message || err) });
    }
  });

  socket.on("chatMessage", ({ message }) => {
    const roomId = socket.data.roomId;
    const username = socket.data.username;
    if (!roomId || !username || !message) return;
    const room = chatRooms.get(roomId);
    if (!room) return;

    const msg = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      username,
      message: String(message).slice(0, 2000),
      ts: Date.now()
    };

    room.history.push(msg);
    if (room.history.length > HISTORY_LIMIT) {
      room.history.splice(0, room.history.length - HISTORY_LIMIT);
    }

    io.to(roomId).emit("chatMessage", msg);
  });

  socket.on("typing", (isTyping) => {
    const roomId = socket.data.roomId;
    const username = socket.data.username;
    if (!roomId || !username) return;
    socket.to(roomId).emit("typing", { username, isTyping: !!isTyping });
  });

  socket.on("leaveRoom", () => leaveRoom(socket));
  socket.on("disconnect", () => {
    leaveRoom(socket);
  });
});

function leaveRoom(socket) {
  const roomId = socket.data.roomId;
  const username = socket.data.username;
  if (!roomId) return;
  const room = chatRooms.get(roomId);
  if (room) {
    room.members.delete(socket.id);
    socket.leave(roomId);
    io.to(roomId).emit("roomUsers", Array.from(room.members.values()).map(v => v.username));
    io.to(roomId).emit("systemMessage", { type: "leave", text: `${username || "알 수 없음"} 님이 퇴장했습니다.`, ts: Date.now() });
  }
  socket.data.roomId = null;
}

// ---------------------- 서버 시작 ----------------------
async function start() {
  try {
    await initMongo();
    server.listen(PORT, () => {
      console.log(`TMAP API server (V7) on http://localhost:${PORT}`);
      console.log(`Similarity cfg:`, CFG.similarity);
      console.log(`MongoDB: db='${CFG.mongoDb}', matches='${CFG.mongoCol}', users='${CFG.usersCol}', coupons='${CFG.couponsCol}'`);
    });
  } catch (err) {
    console.error("Failed to start server:", err);
    process.exit(1);
  }
}

start();


