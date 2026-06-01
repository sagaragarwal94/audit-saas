import OpenAI from "openai";

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function POST(request: Request) {
  const body = await request.json();
  const response = await client.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: body.prompt }]
  });
  console.log("prompt", body.prompt, response);
  return Response.json(response);
}
