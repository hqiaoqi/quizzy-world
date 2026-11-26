// Redeploy after configuring admin bootstrap secret
const ALLOWED_ORIGIN = "https://quizzy-world.pages.dev";
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const PBKDF2_ITERATIONS = 100000

function json(data, status = 200, origin = ALLOWED_ORIGIN) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400",
      "Cache-Control": "no-store",
      "Vary": "Origin"
    }
  });
}

function getOrigin(request) {
  const origin = request.headers.get("Origin");
  return origin === ALLOWED_ORIGIN ? origin : ALLOWED_ORIGIN;
}

function parseJson(value, fallback = null) {
  if (!value) return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64Url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(
    normalized + "=".repeat((4 - normalized.length % 4) % 4)
  );
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function constantTimeEqual(a, b) {
  const aa = new TextEncoder().encode(String(a));
  const bb = new TextEncoder().encode(String(b));

  let diff = aa.length ^ bb.length;
  const length = Math.max(aa.length, bb.length);

  for (let i = 0; i < length; i++) {
    diff |= (aa[i] || 0) ^ (bb[i] || 0);
  }

  return diff === 0;
}

async function sha256(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
  return base64Url(new Uint8Array(digest));
}

async function hashPassword(
  password,
  salt = crypto.getRandomValues(new Uint8Array(16))
) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  return `pbkdf2$${PBKDF2_ITERATIONS}$${base64Url(salt)}$${base64Url(new Uint8Array(bits))}`;
}

async function verifyPassword(password, stored) {
  const parts = String(stored || "").split("$");

  if (parts.length !== 4 || parts[0] !== "pbkdf2") {
    return false;
  }

  const iterations = Number(parts[1]);

  if (
    !Number.isInteger(iterations) ||
    iterations < 100000 ||
    iterations > 1000000
  ) {
    return false;
  }

  const salt = fromBase64Url(parts[2]);
  const expected = parts[3];

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256"
    },
    key,
    256
  );

  return constantTimeEqual(
    base64Url(new Uint8Array(bits)),
    expected
  );
}

async function readBody(request) {
  const length = Number(request.headers.get("Content-Length") || 0);

  if (length > 12000) {
    throw new Error("Request body too large");
  }

  const body = await request.json();

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("Invalid JSON body");
  }

  return body;
}

function validEmail(email) {
  return (
    typeof email === "string" &&
    email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  );
}

async function createSession(env, adminId) {
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = base64Url(tokenBytes);
  const tokenHash = await sha256(token);

  const expiresAt =
    Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;

  await env.DB.prepare(`
    INSERT INTO admin_sessions
      (admin_user_id, token_hash, expires_at, created_at)
    VALUES (?, ?, ?, datetime('now'))
  `)
    .bind(adminId, tokenHash, expiresAt)
    .run();

  return {
    token,
    expires_at: expiresAt
  };
}

async function authenticateAdmin(request, env) {
  const header = request.headers.get("Authorization") || "";
  const match = header.match(/^Bearer ([A-Za-z0-9_-]{40,60})$/);

  if (!match) return null;

  const tokenHash = await sha256(match[1]);

  const row = await env.DB.prepare(`
    SELECT
      a.id,
      a.email,
      a.role,
      s.id AS session_id
    FROM admin_sessions s
    INNER JOIN admin_users a
      ON a.id = s.admin_user_id
    WHERE
      s.token_hash = ?
      AND s.expires_at > ?
      AND a.is_active = 1
    LIMIT 1
  `)
    .bind(tokenHash, Math.floor(Date.now() / 1000))
    .first();

  return row || null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const origin = getOrigin(request);

    if (
      request.headers.get("Origin") &&
      request.headers.get("Origin") !== ALLOWED_ORIGIN
    ) {
      return json({ error: "Origin not allowed" }, 403, ALLOWED_ORIGIN);
    }

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Access-Control-Max-Age": "86400",
          "Vary": "Origin"
        }
      });
    }

    try {
      if (!env.DB) {
        return json({ error: "D1 binding DB not found" }, 500, origin);
      }
// 檢查管理員初始化設定
if (
  path === "/api/admin/bootstrap-status" &&
  request.method === "GET"
) {
  return json({
    success: true,
    configured: Boolean(env.ADMIN_BOOTSTRAP_SECRET)
  }, 200, origin);
}
      // 初始化第一個管理員
      if (
        path === "/api/admin/bootstrap" &&
        request.method === "POST"
      ) {
        if (!env.ADMIN_BOOTSTRAP_SECRET) {
          return json(
            { error: "Admin bootstrap is not configured" },
            503,
            origin
          );
        }

        const body = await readBody(request);
        const suppliedSecret = String(body.bootstrap_secret || "");

        if (
          !constantTimeEqual(
            suppliedSecret,
            env.ADMIN_BOOTSTRAP_SECRET
          )
        ) {
          return json({ error: "Unauthorized" }, 401, origin);
        }

        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");

        if (!validEmail(email)) {
          return json({ error: "Invalid email" }, 400, origin);
        }

        if (password.length < 14 || password.length > 128) {
          return json(
            { error: "Password must be 14 to 128 characters" },
            400,
            origin
          );
        }

        const count = await env.DB.prepare(
          "SELECT COUNT(*) AS total FROM admin_users"
        ).first();

        if (Number(count?.total || 0) !== 0) {
          return json(
            { error: "Bootstrap is closed because an admin already exists" },
            409,
            origin
          );
        }

        const passwordHash = await hashPassword(password);

        const inserted = await env.DB.prepare(`
          INSERT INTO admin_users
            (email, password_hash, role, is_active, created_at)
          SELECT ?, ?, 'admin', 1, datetime('now')
          WHERE NOT EXISTS (
            SELECT 1 FROM admin_users
          )
        `)
          .bind(email, passwordHash)
          .run();

        if (!inserted.meta?.changes) {
          return json(
            { error: "Bootstrap already completed" },
            409,
            origin
          );
        }

        const admin = await env.DB.prepare(`
          SELECT id, email, role
          FROM admin_users
          WHERE email = ?
          LIMIT 1
        `)
          .bind(email)
          .first();

        return json({ success: true, admin }, 201, origin);
      }

      // 管理員登入
      if (
        path === "/api/admin/login" &&
        request.method === "POST"
      ) {
        const body = await readBody(request);

        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");

        if (!validEmail(email) || !password || password.length > 128) {
          return json(
            { error: "Invalid email or password" },
            400,
            origin
          );
        }

        const admin = await env.DB.prepare(`
          SELECT id, email, password_hash, role, is_active
          FROM admin_users
          WHERE email = ?
          LIMIT 1
        `)
          .bind(email)
          .first();

        const valid =
          admin &&
          admin.is_active === 1 &&
          await verifyPassword(password, admin.password_hash);

        if (!valid) {
          return json(
            { error: "Invalid email or password" },
            401,
            origin
          );
        }

        await env.DB.prepare(`
          UPDATE admin_users
          SET last_login_at = datetime('now')
          WHERE id = ?
        `)
          .bind(admin.id)
          .run();

        const session = await createSession(env, admin.id);

        return json(
          {
            success: true,
            admin: {
              id: admin.id,
              email: admin.email,
              role: admin.role
            },
            ...session
          },
          200,
          origin
        );
      }

      // 查詢目前登入的管理員
      if (
        path === "/api/admin/me" &&
        request.method === "GET"
      ) {
        const admin = await authenticateAdmin(request, env);

        if (!admin) {
          return json({ error: "Unauthorized" }, 401, origin);
        }

        return json(
          {
            success: true,
            admin: {
              id: admin.id,
              email: admin.email,
              role: admin.role
            }
          },
          200,
          origin
        );
      }

      // 管理員登出
      if (
        path === "/api/admin/logout" &&
        request.method === "POST"
      ) {
        const header = request.headers.get("Authorization") || "";
        const match = header.match(/^Bearer ([A-Za-z0-9_-]{40,60})$/);

        if (match) {
          await env.DB.prepare(`
            DELETE FROM admin_sessions
            WHERE token_hash = ?
          `)
            .bind(await sha256(match[1]))
            .run();
        }

        return json({ success: true }, 200, origin);
      }


      // 管理後台：新增測驗（3 題、每題 4 選項、4 組結果）
      if (path === "/api/admin/quizzes" && request.method === "POST") {
        const admin = await authenticateAdmin(request, env);
        if (!admin || admin.role !== "admin") {
          return json({ error: "Unauthorized" }, 401, origin);
        }

        const body = await readBody(request);
        const title = String(body.title || "").trim();
        const description = String(body.description || "").trim();
        const categoryId = String(body.category_id || "").trim();
        const coverImage = String(body.cover_image || "✨").trim();
        const status = body.status === "published" ? "published" : "draft";
        const slug = String(body.slug || `quiz-${Date.now()}`).trim().toLowerCase();
        const questions = Array.isArray(body.questions) ? body.questions : [];
        const results = Array.isArray(body.results) ? body.results : [];

        if (!title || title.length > 80 || !description || description.length > 300) {
          return json({ error: "測驗名稱或簡介格式不正確" }, 400, origin);
        }
        if (!/^[a-z0-9-]{3,80}$/.test(slug)) {
          return json({ error: "Slug 僅能使用小寫英文、數字與連字號（3–80 字元）" }, 400, origin);
        }
        if (!["personality","love","emotion","subconscious","career","social","fun"].includes(categoryId)) {
          return json({ error: "請選擇有效的測驗分類" }, 400, origin);
        }
        if (questions.length !== 3 || results.length !== 4) {
          return json({ error: "目前版本需要 3 題與 4 組結果" }, 400, origin);
        }
        for (const q of questions) {
          if (!String(q.text || "").trim() || !Array.isArray(q.options) || q.options.length !== 4 ||
              q.options.some(v => !String(v || "").trim())) {
            return json({ error: "每題都必須填寫題目與 4 個選項" }, 400, origin);
          }
        }
        if (results.some(r => !String(r.title || "").trim() || !String(r.description || "").trim())) {
          return json({ error: "請完整填寫 4 組結果名稱與描述" }, 400, origin);
        }

        const insertedQuiz = await env.DB.prepare(`
          INSERT INTO quizzes
            (slug, category_id, cover_image, status, is_featured, scoring_config_json)
          VALUES (?, ?, ?, ?, 0, ?)
        `).bind(
          slug, categoryId, coverImage, status,
          JSON.stringify({ answer_index_to_result_index: [0,1,2,3] })
        ).run();

        const quizId = insertedQuiz.meta?.last_row_id;
        if (!quizId) throw new Error("Quiz insert did not return an ID");

        await env.DB.prepare(`
          INSERT INTO quiz_translations
            (quiz_id, language, title, description, instructions)
          VALUES (?, 'zh-TW', ?, ?, ?)
        `).bind(quizId, title, description, "選擇最符合你的答案，完成所有題目後查看結果。").run();

        for (let qi = 0; qi < questions.length; qi++) {
          const q = questions[qi];
          const insertedQuestion = await env.DB.prepare(`
            INSERT INTO questions (quiz_id, question_order, question_type, is_required)
            VALUES (?, ?, 'single_choice', 1)
          `).bind(quizId, qi + 1).run();

          const questionId = insertedQuestion.meta?.last_row_id;
          if (!questionId) throw new Error("Question insert did not return an ID");

          await env.DB.prepare(`
            INSERT INTO question_translations (question_id, language, question_text)
            VALUES (?, 'zh-TW', ?)
          `).bind(questionId, String(q.text).trim()).run();

          for (let oi = 0; oi < 4; oi++) {
            await env.DB.prepare(`
              INSERT INTO options
                (question_id, option_order, label_zh, label_en, score_key, score_value)
              VALUES (?, ?, ?, ?, ?, ?)
            `).bind(
              questionId, oi + 1, String(q.options[oi]).trim(),
              String(q.options[oi]).trim(), String(oi), 0
            ).run();
          }
        }

        for (let ri = 0; ri < results.length; ri++) {
          const r = results[ri];
          const insertedResult = await env.DB.prepare(`
            INSERT INTO results (quiz_id, result_key, criteria_json, result_order)
            VALUES (?, ?, ?, ?)
          `).bind(
            quizId, `type-${ri + 1}`,
            JSON.stringify({ answer_index: ri }), ri + 1
          ).run();

          const resultId = insertedResult.meta?.last_row_id;
          if (!resultId) throw new Error("Result insert did not return an ID");

          await env.DB.prepare(`
            INSERT INTO result_translations
              (result_id, language, title, description, advice)
            VALUES (?, 'zh-TW', ?, ?, ?)
          `).bind(
            resultId, String(r.title).trim(),
            String(r.description).trim(), ""
          ).run();
        }

        return json({
          success: true,
          message: status === "published" ? "測驗已建立並發布" : "測驗已儲存為草稿",
          data: { id: quizId, slug, status }
        }, 201, origin);
      }


      // 管理後台：匯出完整測驗資料（題目、選項與結果），供封面與結果圖卡製作使用
      if (path === "/api/admin/export-results" && request.method === "GET") {
        const admin = await authenticateAdmin(request, env);
        if (!admin || admin.role !== "admin") {
          return json({ error: "Unauthorized" }, 401, origin);
        }

        const quizzes = await env.DB.prepare(`
          SELECT q.id AS quiz_id, q.slug, qt.title AS quiz_title,
            qt.description AS quiz_description
          FROM quizzes q
          LEFT JOIN quiz_translations qt
            ON qt.quiz_id = q.id AND qt.language = 'zh-TW'
          ORDER BY q.id
        `).all();

        const data = [];
        for (const quiz of (quizzes.results || [])) {
          const questions = await env.DB.prepare(`
            SELECT q.id AS question_id, q.question_order,
              qt.question_text
            FROM questions q
            LEFT JOIN question_translations qt
              ON qt.question_id = q.id AND qt.language = 'zh-TW'
            WHERE q.quiz_id = ?
            ORDER BY q.question_order
          `).bind(quiz.quiz_id).all();

          const options = await env.DB.prepare(`
            SELECT o.id AS option_id, o.question_id, o.option_order,
              o.label_zh, o.label_en
            FROM options o
            INNER JOIN questions q ON q.id = o.question_id
            WHERE q.quiz_id = ?
            ORDER BY q.question_order, o.option_order
          `).bind(quiz.quiz_id).all();

          const results = await env.DB.prepare(`
            SELECT r.id AS result_id, r.result_order,
              rt.title AS result_title, rt.description AS result_description,
              rt.advice AS result_advice
            FROM results r
            LEFT JOIN result_translations rt
              ON rt.result_id = r.id AND rt.language = 'zh-TW'
            WHERE r.quiz_id = ?
            ORDER BY r.result_order
          `).bind(quiz.quiz_id).all();

          data.push({
            ...quiz,
            questions: questions.results || [],
            options: options.results || [],
            results: results.results || []
          });
        }
        return json({ success: true, data }, 200, origin);
      }

      // 社群心理測驗投稿：存入 D1 並可選擇透過 Resend 通知管理員
      if (path === "/api/submissions" && request.method === "POST") {
        const body = await readBody(request);
        const title = String(body.title || "").trim();
        const detail = String(body.detail || "").trim();
        const email = String(body.email || "").trim();
        if (!title || title.length > 120 || !detail || detail.length > 2000 || (email && !validEmail(email))) {
          return json({ error: "投稿內容格式不正確" }, 400, origin);
        }
        await env.DB.prepare(`CREATE TABLE IF NOT EXISTS quiz_submissions (
          id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, detail TEXT NOT NULL,
          email TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')), status TEXT NOT NULL DEFAULT 'new'
        )`).run();
        const saved = await env.DB.prepare("INSERT INTO quiz_submissions (title,detail,email) VALUES (?,?,?)").bind(title,detail,email||null).run();
        let notified = false;
        if (env.RESEND_API_KEY && env.RESEND_FROM) {
          const mail = await fetch("https://api.resend.com/emails", {
            method:"POST", headers:{"Authorization":"Bearer "+env.RESEND_API_KEY,"Content-Type":"application/json"},
            body:JSON.stringify({from:env.RESEND_FROM,to:["hqiaoqi@gmail.com"],subject:"[Quizzy World 投稿] "+title,
              text:"投稿："+title+"\n\n內容：\n"+detail+"\n\nEmail："+(email||"未提供")+"\n\n投稿已存入網站資料庫。" })
          });
          notified = mail.ok;
        }
        return json({success:true,id:saved.meta?.last_row_id,notified},201,origin);
      }

      if (path === "/api/admin/submissions" && request.method === "GET") {
        const admin = await authenticateAdmin(request, env);
        if (!admin || admin.role !== "admin") return json({error:"Unauthorized"},401,origin);
        await env.DB.prepare(`CREATE TABLE IF NOT EXISTS quiz_submissions (
          id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, detail TEXT NOT NULL,
          email TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')), status TEXT NOT NULL DEFAULT 'new'
        )`).run();
        const rows = await env.DB.prepare("SELECT id,title,detail,email,created_at,status FROM quiz_submissions ORDER BY id DESC LIMIT 200").all();
        return json({success:true,data:rows.results||[]},200,origin);
      }

      if (request.method !== "GET") {
        return json({ error: "Method not allowed" }, 405, origin);
      }
// 管理後台：取得所有測驗（包含未發布測驗）
if (
  path === "/api/admin/quizzes" &&
  request.method === "GET"
) {
  const admin = await authenticateAdmin(request, env);

  if (!admin || admin.role !== "admin") {
    return json({ error: "Unauthorized" }, 401, origin);
  }

  const lang = url.searchParams.get("lang") || "zh-TW";

  const result = await env.DB.prepare(`
    SELECT
      q.id,
      q.slug,
      q.category_id,
      q.cover_image,
      q.status,
      q.is_featured,
      t.language,
      t.title,
      t.description,
      (
        SELECT COUNT(*)
        FROM questions questions_count
        WHERE questions_count.quiz_id = q.id
      ) AS question_count,
      (
        SELECT COUNT(*)
        FROM results results_count
        WHERE results_count.quiz_id = q.id
      ) AS result_count
    FROM quizzes q
    LEFT JOIN quiz_translations t
      ON t.quiz_id = q.id
      AND t.language = ?
    ORDER BY q.id DESC
  `)
    .bind(lang)
    .all();

  return json(
    {
      success: true,
      language: lang,
      data: result.results || []
    },
    200,
    origin
  );
}
      // Worker 與 D1 連線測試
      if (path === "/api/health") {
        await env.DB.prepare("SELECT 1").first();

        return json(
          {
            success: true,
            message: "Quizzy World API is running",
            database: "connected"
          },
          200,
          origin
        );
      }

      // 取得測驗分類
      if (path === "/api/categories") {
        const result = await env.DB.prepare(`
          SELECT *
          FROM categories
          ORDER BY id
        `).all();

        return json(
          {
            success: true,
            data: result.results || []
          },
          200,
          origin
        );
      }

      // 公開：完成測驗，累積全站參與人次
      const completionMatch = path.match(/^\/api\/quizzes\/([^/]+)\/complete$/);
      if (completionMatch && request.method === "POST") {
        const slug = decodeURIComponent(completionMatch[1]);
        await env.DB.prepare(`CREATE TABLE IF NOT EXISTS quiz_play_stats (quiz_id INTEGER PRIMARY KEY, plays INTEGER NOT NULL DEFAULT 0)`).run();
        const quiz = await env.DB.prepare("SELECT id FROM quizzes WHERE slug = ? AND status = 'published' LIMIT 1").bind(slug).first();
        if (!quiz) return json({ error: "Quiz not found" }, 404, origin);
        await env.DB.prepare("INSERT INTO quiz_play_stats (quiz_id, plays) VALUES (?, 1) ON CONFLICT(quiz_id) DO UPDATE SET plays = plays + 1").bind(quiz.id).run();
        const updated = await env.DB.prepare("SELECT plays FROM quiz_play_stats WHERE quiz_id = ?").bind(quiz.id).first();
        return json({ success: true, plays: Number(updated?.plays || 0) }, 200, origin);
      }

      // Ensure play counter table exists before public listing
      if (path === "/api/quizzes" && request.method === "GET") {
        await env.DB.prepare(`CREATE TABLE IF NOT EXISTS quiz_play_stats (quiz_id INTEGER PRIMARY KEY, plays INTEGER NOT NULL DEFAULT 0)`).run();
      }
      // 取得已發布測驗
      if (path === "/api/quizzes") {
        const lang = url.searchParams.get("lang") || "zh-TW";

        const result = await env.DB.prepare(`
          SELECT
            q.id,
            q.slug,
            q.category_id,
            q.cover_image,
            q.status,
            q.is_featured,
            COALESCE(ps.plays, 0) AS plays,
            t.language,
            t.title,
            t.description,
            t.instructions
          FROM quizzes q
          LEFT JOIN quiz_play_stats ps ON ps.quiz_id = q.id
          LEFT JOIN quiz_translations t
            ON t.quiz_id = q.id
            AND t.language = ?
          WHERE q.status = 'published'
          ORDER BY q.is_featured DESC, q.id DESC
        `)
          .bind(lang)
          .all();

        return json(
          {
            success: true,
            language: lang,
            data: result.results || []
          },
          200,
          origin
        );
      }

      // 取得單一測驗詳細資料
      const quizMatch = path.match(/^\/api\/quizzes\/([^/]+)$/);

      if (quizMatch) {
        const slug = decodeURIComponent(quizMatch[1]);
        const lang = url.searchParams.get("lang") || "zh-TW";

        const quiz = await env.DB.prepare(`
          SELECT
            q.*,
            t.language,
            t.title,
            t.description,
            t.instructions
          FROM quizzes q
          LEFT JOIN quiz_translations t
            ON t.quiz_id = q.id
            AND t.language = ?
          WHERE q.slug = ?
            AND q.status = 'published'
          LIMIT 1
        `)
          .bind(lang, slug)
          .first();

        if (!quiz) {
          return json({ error: "Quiz not found" }, 404, origin);
        }

        const questions = await env.DB.prepare(`
          SELECT
            q.id,
            q.question_order,
            q.question_type,
            q.is_required,
            qt.question_text
          FROM questions q
          LEFT JOIN question_translations qt
            ON qt.question_id = q.id
            AND qt.language = ?
          WHERE q.quiz_id = ?
          ORDER BY q.question_order
        `)
          .bind(lang, quiz.id)
          .all();

        const options = await env.DB.prepare(`
          SELECT
            o.id,
            o.question_id,
            o.option_order,
            o.label_zh,
            o.label_en,
            o.score_key,
            o.score_value
          FROM options o
          INNER JOIN questions q
            ON q.id = o.question_id
          WHERE q.quiz_id = ?
          ORDER BY q.question_order, o.option_order
        `)
          .bind(quiz.id)
          .all();

        const results = await env.DB.prepare(`
          SELECT
            r.id,
            r.result_key,
            r.criteria_json,
            r.result_order,
            rt.language,
            rt.title,
            rt.description,
            rt.advice
          FROM results r
          LEFT JOIN result_translations rt
            ON rt.result_id = r.id
            AND rt.language = ?
          WHERE r.quiz_id = ?
          ORDER BY r.result_order
        `)
          .bind(lang, quiz.id)
          .all();

        return json(
          {
            success: true,
            language: lang,
            data: {
              ...quiz,
              scoring_config: parseJson(quiz.scoring_config_json),
              questions: questions.results || [],
              options: options.results || [],
              results: (results.results || []).map(item => ({
                ...item,
                criteria: parseJson(item.criteria_json)
              }))
            }
          },
          200,
          origin
        );
      }

      return json({ error: "API endpoint not found" }, 404, origin);
  } catch (error) {
  console.error("Worker API Error:", error);

  return json(
    {
      success: false,
      error: "Internal server error"
    },
    500,
    origin
  );
}
  }
};
