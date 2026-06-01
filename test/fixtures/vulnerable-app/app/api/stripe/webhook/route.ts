import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(request: Request) {
  const event = await request.json();
  console.log("stripe payload", event);
  if (event.type === "checkout.session.completed") {
    return Response.json({ ok: true, event });
  }
  return Response.json({ ok: true });
}
