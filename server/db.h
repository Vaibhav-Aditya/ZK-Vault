#pragma once
#include <sqlite3.h>
#include <string>

sqlite3* db;

void init_db() {
    sqlite3_open("users.db", &db);

    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS users("
        "id TEXT PRIMARY KEY, pubkey BLOB);", 0,0,0);

    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS sessions("
        "token TEXT PRIMARY KEY, user TEXT);", 0,0,0);
}

void add_user(const std::string& id, const std::string& pub) {
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db,
        "INSERT INTO users VALUES(?,?);", -1, &stmt, NULL);

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, pub.data(), pub.size(), SQLITE_STATIC);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::string get_pubkey(const std::string& id) {
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db,
        "SELECT pubkey FROM users WHERE id=?;",
        -1, &stmt, NULL);

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_STATIC);

    std::string res;

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const void* data = sqlite3_column_blob(stmt, 0);
        int size = sqlite3_column_bytes(stmt, 0);
        res = std::string((char*)data, size);
    }

    sqlite3_finalize(stmt);
    return res;
}

void add_session(const std::string& token, const std::string& user) {
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db,
        "INSERT INTO sessions VALUES(?,?);",
        -1, &stmt, NULL);

    sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user.c_str(), -1, SQLITE_STATIC);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

bool validate_session(const std::string& token, std::string& user) {
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db,
        "SELECT user FROM sessions WHERE token=?;",
        -1, &stmt, NULL);

    sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user = (char*)sqlite3_column_text(stmt, 0);
        sqlite3_finalize(stmt);
        return true;
    }

    sqlite3_finalize(stmt);
    return false;
}
