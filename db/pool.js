const { Pool } = require("pg");

module.exports = new Pool({
    host: "localhost",
    user: "postgres",
    password: "@@!!wwaa",
    database: "clubhouse",
    port: 5432,
  });