#include "httplib.h"
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <unordered_map>
#include <fstream>
#include "crypto.h"
#include "db.h"

using namespace httplib;
using namespace std;

string gen_nonce() {
    unsigned char buf[16];
    RAND_bytes(buf, 16);
    return string((char*)buf, 16);
}

string gen_token() {
    unsigned char buf[32];
    RAND_bytes(buf, 32);
    return string((char*)buf, 32);
}

int main() {
    init_db();

    Server svr;

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX* ctx = BN_CTX_new();

    unordered_map<string, string> nonces;

    // REGISTER
    svr.Post("/register", [&](const Request& req, Response& res) {
        string user = req.get_param_value("user");
        add_user(user, req.body);
        res.set_content("ok", "text/plain");
    });

    // GET NONCE
    svr.Get("/nonce", [&](const Request& req, Response& res) {
        string user = req.get_param_value("user");
        string n = gen_nonce();
        nonces[user] = n;
        res.set_content(n, "application/octet-stream");
    });

    // LOGIN
    svr.Post("/login", [&](const Request& req, Response& res) {
        string user = req.get_param_value("user");
        string pub = get_pubkey(user);
        if (pub.empty()) { res.status = 403; return; }

        string nonce = nonces[user];

        string R_bytes = req.body.substr(0, 65);
        string s_bytes = req.body.substr(65);

        EC_POINT* R = EC_POINT_new(group);
        EC_POINT_oct2point(group, R,
            (unsigned char*)R_bytes.data(), 65, ctx);

        BIGNUM* s = BN_bin2bn(
            (unsigned char*)s_bytes.data(),
            s_bytes.size(), NULL);

        EC_POINT* Y = EC_POINT_new(group);
        EC_POINT_oct2point(group, Y,
            (unsigned char*)pub.data(), pub.size(), ctx);

        BIGNUM* c = hash_to_bn(group, R, Y, nonce);

        EC_POINT* sG = EC_POINT_new(group);
        EC_POINT_mul(group, sG, s, NULL, NULL, ctx);

        EC_POINT* cY = EC_POINT_new(group);
        EC_POINT_mul(group, cY, NULL, Y, c, ctx);

        EC_POINT* rhs = EC_POINT_new(group);
        EC_POINT_add(group, rhs, R, cY, ctx);

        if (EC_POINT_cmp(group, sG, rhs, ctx) == 0) {
            string token = gen_token();
            add_session(token, user);
            res.set_content(token, "application/octet-stream");
        } else {
            res.status = 403;
        }
    });

    // UPLOAD
    svr.Post("/upload", [&](const Request& req, Response& res) {
    string token = req.get_param_value("token");   // ✅ FIX
    string filename = req.get_param_value("file");
    string user;

    if (!validate_session(token, user)) {          // ✅ FIX
        res.status = 403; 
        return;
    }

    // 🚨 security check
    if (filename.find("..") != string::npos) {
        res.status = 400;
        return;
    }

    ofstream f("vault/" + user + "_" + filename, ios::binary);
    f.write(req.body.data(), req.body.size());

    res.set_content("stored", "text/plain");
});
    // DOWNLOAD
    svr.Get("/download", [&](const Request& req, Response& res) {
    string token = req.get_param_value("token");   // ✅ FIX
    string filename = req.get_param_value("file");
    string user;

    if (!validate_session(token, user)) {          // ✅ FIX
        res.status = 403; 
        return;
    }

    // 🚨 security check
    if (filename.find("..") != string::npos) {
        res.status = 400;
        return;
    }

    ifstream f("vault/" + user + "_" + filename, ios::binary);

    if (!f) {                                     // ✅ IMPORTANT
        res.status = 404;
        res.set_content("file not found", "text/plain");
        return;
    }

    string data((istreambuf_iterator<char>(f)), {});
    res.set_content(data, "application/octet-stream");
});

    int port = getenv("PORT") ? stoi(getenv("PORT")) : 8080;
    svr.listen("0.0.0.0", port);
}
