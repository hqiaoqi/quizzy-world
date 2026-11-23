
const ALLOWED_ORIGIN = "https://quizzy-world.pages.dev";

function json(data, status = 200, origin = ALLOWED_ORIGIN) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const origin = getOrigin(request);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Methods": "GET, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
          "Vary": "Origin"
        }
      });
    }

    if (request.method !== "GET") {
      return json({ error: "Method not allowed" }, 405, origin);
    }

    try {
      if (!env.DB) {
        return json({ error: "D1 binding DB not found" }, 500, origin);
      }

      // 1. Worker 與 D1 連線測試
      if (path === "/api/health") {
        await env.DB.prepare("SELECT 1").first();

        return json({
          success: true,
          message: "Quizzy World API is running",
          database: "connected"
        }, 200, origin);
      }

      // 2. 取得測驗分類
      if (path === "/api/categories") {
        const result = await env.DB
          .prepare("SELECT * FROM categories ORDER BY id")
          .all();

        return json({
          success: true,
          data: result.results || []
        }, 200, origin);
      }

      // 3. 取得已發布測驗
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
            t.language,
            t.title,
            t.description,
            t.instructions
          FROM quizzes q
          LEFT JOIN quiz_translations t
            ON t.quiz_id = q.id
            AND t.language = ?
          WHERE q.status = 'published'
          ORDER BY q.is_featured DESC, q.id DESC
        `).bind(lang).all();

        return json({
          success: true,
          language: lang,
          data: result.results || []
        }, 200, origin);
      }

      // 4. 取得單一測驗詳細資料
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
        `).bind(lang, slug).first();

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
        `).bind(lang, quiz.id).all();

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
        `).bind(quiz.id).all();

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
        `).bind(lang, quiz.id).all();

        return json({
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
        }, 200, origin);
      }

      return json({ error: "API endpoint not found" }, 404, origin);

    } catch (error) {
      return json({
        success: false,
        error: "Internal server error",
        detail: error.message
      }, 500, origin);
    }
  }
};

