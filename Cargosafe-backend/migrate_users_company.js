const Database = require("better-sqlite3");
const db = new Database("./cargosafe.db");

function addCol(sql){
  try{
    db.prepare(sql).run();
    console.log("OK:", sql);
  }catch(e){
    // Hvis kolonnen allerede findes, ignorer vi fejlen
    if(String(e.message).includes("duplicate column name")){
      console.log("SKIP (exists):", sql);
    }else{
      console.error("ERROR:", e.message);
      process.exit(1);
    }
  }
}

addCol("ALTER TABLE users ADD COLUMN company_name TEXT");
addCol("ALTER TABLE users ADD COLUMN cvr TEXT");
addCol("ALTER TABLE users ADD COLUMN company_address TEXT");
addCol("ALTER TABLE users ADD COLUMN contact_name TEXT");
addCol("ALTER TABLE users ADD COLUMN contact_phone TEXT");
addCol("ALTER TABLE users ADD COLUMN contact_email TEXT");

console.log("Done ✅");
db.close();