export const db = {
  project: {
    async findUnique(query: unknown) {
      return { id: "project_1", query };
    }
  },
  async query(sql: string) {
    return { sql };
  }
};
