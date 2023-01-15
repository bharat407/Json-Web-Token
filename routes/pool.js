var mysql = require("mysql");
var pool = mysql.createConnection({
  host: "localhost",
  port: 3306,
  database: "rgpv",
  user: "root",
  password: "1234",
  multipleStatements: true,
});
module.exports = pool;
