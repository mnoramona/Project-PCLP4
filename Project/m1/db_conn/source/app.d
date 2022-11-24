import std.algorithm.searching;
import std.conv;
import std.digest;
import std.digest.sha;
import std.range;
import std.stdio;
import std.string;
import std.typecons;
import std.net.isemail;

import vibe.db.mongo.mongo : connectMongoDB, MongoClient, MongoCollection;
import vibe.data.bson;

import dauth : makeHash, toPassword, parseHash;

struct DBConnection
{
    enum UserRet
    {
        OK,
        ERR_NULL_PASS,
        ERR_USER_EXISTS,
        ERR_INVALID_EMAIL,
        ERR_WRONG_USER,
        ERR_WRONG_PASS,
        NOT_IMPLEMENTED
    }

    MongoClient client;
    MongoCollection users;
    MongoCollection files;
    MongoCollection URLs;

    struct User
    {
        string email;
        string username;
        string password;
        string name;
        string description;
    }

    this(string dbUser, string dbPassword, string dbAddr, string dbPort, string dbName)
    {
        string mongo;
        // MongoClient client = connectMongoDB("mongodb://root:example@127.0.0.1:27017/");
        mongo = "mongodb://" ~ dbUser ~ ":" ~ dbPassword ~ "@" ~ dbAddr ~ ":" ~ dbPort ~ "/";
        client = connectMongoDB(mongo);

        users = client.getCollection(dbName ~ ".users");
        files = client.getCollection(dbName ~ ".files");
        URLs = client.getCollection(dbName ~ ".URLs");
    }

    UserRet addUser(string email, string username, string password, string name = "", string desc = "")
    {
        if(!isEmail(email)){
            return UserRet.ERR_INVALID_EMAIL;
        }

        if(password == null){
            return UserRet.ERR_NULL_PASS;
        }
        
        auto findEmail = users.findOne(["email": email]);
        if(findEmail != Bson(null)){
            return UserRet.ERR_USER_EXISTS;
        }

        users.insert(["email": email, "username": username, "password": password, "name": name, "desc": desc]);  
        return UserRet.OK;
    }

    UserRet authUser(string email, string password)
    {
        if(!isEmail(email)){
            return UserRet.ERR_INVALID_EMAIL;
        }

        if(password == null){
            return UserRet.ERR_NULL_PASS;
        }
        
        auto findEmail = users.findOne(["email": email]);
        if(findEmail == Bson(null)){
            return UserRet.ERR_WRONG_USER;
        }

        auto findEmailsPass = users.findOne(["email": email, "password": password]);
        if(findEmailsPass == Bson(null)){
            return UserRet.ERR_WRONG_PASS;
        }

        return UserRet.OK;
    }

    UserRet deleteUser(string email)
    {
        users.remove(["email" : email]);
        return UserRet.OK;
    }

    struct File
    {
        @name("_id") BsonObjectID id; // represented as _id in the db
        string userId;
        ubyte[] binData;
        string fileName;
        string digest; // unique
        string securityLevel;
    }

    enum FileRet
    {
        OK,
        FILE_EXISTS,
        ERR_EMPTY_FILE,
        NOT_IMPLEMENTED
    }

    FileRet addFile(string userId, ubyte[] binData, string fileName)
    {
        //files.remove();
        File helpfile;
        helpfile.userId = userId;
        helpfile.binData = binData;
        helpfile.fileName = fileName;
        //string sec = "";

        auto dataDigest = digest!SHA512(helpfile.binData).toHexString().to!string;
        helpfile.digest = dataDigest;
        
        if(helpfile.binData == null){
            return FileRet.ERR_EMPTY_FILE;
        }
        
        auto findDigest = files.findOne(["digest": dataDigest]);
        if(findDigest != Bson(null)){
            return FileRet.FILE_EXISTS;
        }

        files.insert(helpfile);  

        return FileRet.OK;
    }

    File[] getFiles(string userId)
    {
        File[] fs;

        auto findUser = files.find(["userId": userId]);
        foreach(f; findUser){
            fs ~= deserializeBson!File(f);
        }

        return fs;
    }

    Nullable!File getFile(string digest)
    in(!digest.empty)
    do
    {
        Nullable!File file;
        
        auto findDigest = files.findOne(["digest": digest]);
        if(!findDigest.isNull) file = deserializeBson!File(findDigest);

        return file;
    }

    void deleteFile(string digest)
    in(!digest.empty)
    do
    {
        files.remove(["digest" : digest]);
    }

    struct Url
    {
        @name("_id") BsonObjectID id; // represented as _id in the db
        string userId;
        string addr;
        string securityLevel;
        string[] aliases;
    }

    enum UrlRet
    {
        OK,
        URL_EXISTS,
        ERR_EMPTY_URL,
        NOT_IMPLEMENTED
    }

    UrlRet addUrl(string userId, string urlAddress)
    {   
        Url helpurl;
        helpurl.userId = userId;
        helpurl.addr = urlAddress;

        if(helpurl.addr == null){
            return UrlRet.ERR_EMPTY_URL;
        }
        
        auto findAddress = URLs.findOne(["addr": helpurl.addr]);
        if(findAddress != Bson(null)){
            return UrlRet.URL_EXISTS;
        }

        URLs.insert(helpurl);  

        return UrlRet.OK;
    }

    Url[] getUrls(string userId)
    {
        Url[] us;

        auto findUser = URLs.find(["userId": userId]);
        foreach(u; findUser){
            us ~= deserializeBson!Url(u);
        }

        return us;
    }

    Nullable!Url getUrl(string urlAddress)
    in(!urlAddress.empty)
    do
    {
        Nullable!Url url;

        auto findAddress = URLs.findOne(["addr": urlAddress]);
        if(!findAddress.isNull) url = deserializeBson!Url(findAddress);

        return url;
    }

    void deleteUrl(string urlAddress)
    in(!urlAddress.empty)
    do
    {
        URLs.remove(["addr": urlAddress]);
    }
}
