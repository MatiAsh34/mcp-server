import { z } from "zod";
import { pool } from "../db/connection.js";

export const executeQueryTool = {
  name: "execute_query",
  schema: {
    query: z.string(),
  },

  handler: async ({ query }) => {
    try {
      const result = await pool.query(query);

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result.rows, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: "Error: " + error.message,
          },
        ],
      };
    }
  },
};