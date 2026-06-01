import { db } from "../../../../lib/db";

export async function GET(_request: Request, { params }: { params: { id: string } }) {
  const project = await db.project.findUnique({
    where: { id: params.id }
  });
  return Response.json(project);
}
