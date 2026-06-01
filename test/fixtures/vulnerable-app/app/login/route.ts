import crypto from "node:crypto";

export async function POST(request: Request) {
  const { email, password } = await request.json();
  const hash = crypto.createHash("sha256").update(password).digest("hex");
  console.log("login", email, password);
  return Response.json({ email, hash });
}
