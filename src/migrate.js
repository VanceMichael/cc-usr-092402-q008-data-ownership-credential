const fs=require('fs'); const path=require('path'); const Database=require('better-sqlite3'); const file=process.env.DATA_CREDENTIAL_DB_PATH||'data/credential.sqlite3'; fs.mkdirSync(path.dirname(file),{recursive:true}); const db=new Database(file); db.exec('CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL)'); db.close();

