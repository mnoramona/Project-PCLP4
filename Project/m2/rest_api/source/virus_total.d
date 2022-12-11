import std.conv;
import std.digest;
import std.digest.sha;
import std.stdio;

import vibe.d;
import vibe.web.auth;

import db_conn;

static struct AuthInfo
{
@safe:
    string userEmail;
}

@path("api/v1")
@requiresAuth
interface VirusTotalAPIRoot
{
    // Users management
    @noAuth
    @method(HTTPMethod.POST)
    @path("signup")
    Json addUser(string userEmail, string username, string password, string name = "", string desc = "");

    @noAuth
    @method(HTTPMethod.POST)
    @path("login")
    Json authUser(string userEmail, string password);

    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_user")
    Json deleteUser(string userEmail);

    // URLs management
    @anyAuth
    @method(HTTPMethod.POST)
    @path("add_url") // the path could also be "/url/add", thus defining the url "namespace" in the URL
    Json addUrl(string userEmail, string urlAddress);

    @noAuth
    @method(HTTPMethod.GET)
    @path("url_info")
    Json getUrlInfo(string urlAddress);

    @noAuth
    @method(HTTPMethod.GET)
    @path ("user_urls")
    Json getUserUrls(string userEmail);

    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_url")
    Json deleteUrl(string userEmail, string urlAddress);

    // Files management
    @anyAuth
    @method(HTTPMethod.POST)
    @path("add_file")
    Json addFile(string userEmail, immutable ubyte[] binData, string fileName);

    @noAuth
    @method(HTTPMethod.GET)
    @path("file_info")
    Json getFileInfo(string fileSHA512Digest);

    @noAuth
    @method(HTTPMethod.GET)
    @path("user_files")
    Json getUserFiles(string userEmail);

    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_file")
    Json deleteFile(string userEmail, string fileSHA512Digest);
}

class VirusTotalAPI : VirusTotalAPIRoot
{
    this(DBConnection dbClient)
    {
        this.dbClient = dbClient;
    }

    @noRoute AuthInfo authenticate(scope HTTPServerRequest req, scope HTTPServerResponse res)
    {
        // If "userEmail" is not present, an error 500 (ISE) will be returned
        string userEmail = req.json["userEmail"].get!string;
        string userAccessToken = dbClient.getUserAccessToken(userEmail);
        // Use headers.get to check if key exists
        string headerAccessToken = req.headers.get("AccessToken");
        if (headerAccessToken && headerAccessToken == userAccessToken)
            return AuthInfo(userEmail);
        throw new HTTPStatusException(HTTPStatus.unauthorized);
    }

override:

    Json addUser(string userEmail, string username, string password, string name = "", string desc = "")
    {
        auto aboutAddUser = dbClient.addUser(userEmail, username, password, name, desc);

        if(aboutAddUser == dbClient.UserRet.ERR_NULL_PASS){
            throw new HTTPStatusException(HTTPStatus.badRequest, "No! No! Null password! No! No!");
        }

        if(aboutAddUser == dbClient.UserRet.ERR_INVALID_EMAIL){
            throw new HTTPStatusException(HTTPStatus.badRequest, "No! No! Invalid email! No! No!");
        }

        if(aboutAddUser == dbClient.UserRet.ERR_USER_EXISTS){
            throw new HTTPStatusException(HTTPStatus.unauthorized, "No! No! This user exists! No! No!");
        }

        if(aboutAddUser == dbClient.UserRet.OK){
            return serializeToJson(aboutAddUser);
        }

       throw new HTTPStatusException(HTTPStatus.internalServerError, "[Internal Server Error] user action not defined");
    }

    Json authUser(string userEmail, string password)
    {
        auto aboutAuthUser = dbClient.authUser(userEmail, password);

        if(aboutAuthUser == dbClient.UserRet.ERR_INVALID_EMAIL){
            throw new HTTPStatusException(HTTPStatus.badRequest, "No! No! Invalid email! No! No!");
        }

        if(aboutAuthUser == dbClient.UserRet.ERR_NULL_PASS){
            throw new HTTPStatusException(HTTPStatus.badRequest, "No! No! Null password! No! No!");
        }

        if(aboutAuthUser == dbClient.UserRet.ERR_WRONG_USER){
            throw new HTTPStatusException(HTTPStatus.unauthorized, "No! No! Wrong user! No! No!");
        }

        if(aboutAuthUser == dbClient.UserRet.ERR_WRONG_PASS){
            throw new HTTPStatusException(HTTPStatus.unauthorized, "No! No! Wrong password! No! No!");
        }

        auto AccessToken = dbClient.getUserAccessToken(userEmail);

        if(aboutAuthUser == dbClient.UserRet.OK){
            return serializeToJson(["AccessToken" : AccessToken]);
        }

        throw new HTTPStatusException(HTTPStatus.internalServerError, "[Internal Server Error] user action not defined");
    }

    Json deleteUser(string userEmail)
    {
        auto aboutDelUser = dbClient.deleteUser(userEmail); 

        if(aboutDelUser == dbClient.UserRet.ERR_INVALID_EMAIL){
            throw new HTTPStatusException(HTTPStatus.unauthorized, "No! No! Invalid email! No! No!");
        }

        if(aboutDelUser == dbClient.UserRet.OK){
            return serializeToJson(aboutDelUser);
        }

        throw new HTTPStatusException(HTTPStatus.internalServerError, "[Internal Server Error] user action not defined");
    }

    // URLs management

    Json addUrl(string userEmail, string urlAddress)
    {
        auto aboutAddUrl = dbClient.addUrl(userEmail, urlAddress);

        if(aboutAddUrl == dbClient.UrlRet.ERR_EMPTY_URL){
            throw new HTTPStatusException(HTTPStatus.badRequest, "No! No! Empty URL! No! No!");
        }

        if(aboutAddUrl == dbClient.UrlRet.URL_EXISTS){
            throw new HTTPStatusException(HTTPStatus.ok, "Oho! URL exists! Oho!");
        }

        if(aboutAddUrl == dbClient.UrlRet.OK){
            return serializeToJson(aboutAddUrl);
        }

        throw new HTTPStatusException(HTTPStatus.internalServerError, "[Internal Server Error] user action not defined");
    }

    Json deleteUrl(string userEmail, string urlAddress)
    {
        if(urlAddress.length == 0){
            throw new HTTPStatusException(HTTPStatus.badRequest, "No! No! Empty URL! No! No!");
        }

        dbClient.deleteUrl(userEmail, urlAddress);

        return serializeToJson(["Conclusion" : "No more URL!" ]);
    }

    Json getUrlInfo(string urlAddress)
    {
        auto aboutGetUrl = dbClient.getUrl(urlAddress);
        
        if(aboutGetUrl.length == 0){
            throw new HTTPStatusException(HTTPStatus.notFound, "No! No! No URL found! No! No!");
        }

        return serializeToJson(aboutGetUrl);
    }

    Json getUserUrls(string userEmail)
    {    
        auto aboutGetUrls = dbClient.getUrls(userEmail);

        return serializeToJson(aboutGetUrls);
    }

    // Files management

    Json addFile(string userEmail, immutable ubyte[] binData, string fileName)
    {
        auto aboutAddFile = dbClient.addFile(userEmail, binData, fileName);

        if(aboutAddFile == dbClient.FileRet.ERR_EMPTY_FILE){
            throw new HTTPStatusException(HTTPStatus.badRequest, "No! No! Empty file! No! No!");
        }

        if(aboutAddFile == dbClient.FileRet.OK){
            return serializeToJson(aboutAddFile);
        }

        if(aboutAddFile == dbClient.FileRet.FILE_EXISTS){
            return serializeToJson(aboutAddFile);
        }
        throw new HTTPStatusException(HTTPStatus.internalServerError, "[Internal Server Error] user action not defined");
    }

    Json getFileInfo(string fileSHA512Digest)
    {
        auto aboutGetFile = dbClient.getFile(fileSHA512Digest);
        
        if(aboutGetFile.length == 0){
            throw new HTTPStatusException(HTTPStatus.notFound, "No! No! No File found! No! No!");
        }

        return serializeToJson(aboutGetFile);
    }

    Json getUserFiles(string userEmail)
    {
        auto aboutGetFiles = dbClient.getFiles(userEmail);
        
        return serializeToJson(aboutGetFiles);
    }

    Json deleteFile(string userEmail, string fileSHA512Digest)
    {
        if(fileSHA512Digest.length == 0){
            throw new HTTPStatusException(HTTPStatus.badRequest, "No! No! Empty file! No! No!");
        }

        dbClient.deleteFile(userEmail, fileSHA512Digest);

        return serializeToJson(["Conclusion" : "No more File!" ]);
        }

private:
    DBConnection dbClient;
}
