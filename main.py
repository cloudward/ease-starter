__author__ = 'Mitul Golakiya'


#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Dev mode access on localhost:8080/?page=test

import webapp2
import io
import os
import datetime
import ease
import logging
import hashlib
from ease.easeGlobal import GlobalCommonVars
from google.appengine.api import datastore
from google.appengine.ext import db
from ease import gspread
import httplib2
from apiclient.discovery import build
from oauth2client.client import OAuth2WebServerFlow
import random
import re
from ease.easeConstants import EaseConstants
import mimetypes
from ease.gaesessions import get_current_session
from oauth2client.client import FlowExchangeError
from apiclient.http import MediaIoBaseUpload
from oauth2client.client import Credentials
from ease.easeGAppUtils import EaseGAppCredentials

global dataObj


class UploadFileToGoogleDrive():
    def __init__(self):
        self.folderId = ""
        self.fileName = ""
        self.fileContent = ""
        self.action = ""
        self.fileId = ""
        self.inputName = ""

    def uploadFile(self):
        resultObj = {}

        credentials = get_stored_credentials()

        if credentials is None:
            resultObj['isSuccess'] = False
            resultObj['error'] = "<div style='text-align: center'><h1>Credentials not found in datastore...<br>Please generate token...</h1></div>"
            return resultObj

        media = ""
        body = ""

        if self.action != EaseConstants.DELETE:
            custom_mime_types = {
                '.psd': 'image/x-photoshop',
                '.air': 'application/x-zip',
                '.apk': 'application/vnd.android.package-archive',
                '.jar': 'application/java-archive',
                '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }

            fileMimeType = ""
            lastDotPos = self.fileName.rfind(".")
            if lastDotPos > -1:
                fileExtension = self.fileName[lastDotPos:]
                mimetypes.init()
                if fileExtension in mimetypes.types_map:
                    fileMimeType = mimetypes.types_map[fileExtension]
                elif fileExtension in custom_mime_types:
                    fileMimeType = custom_mime_types[fileExtension]
                # else:
                #     fileMimeType = "application/vnd.google-apps.unknown"

            fh = io.BytesIO(self.fileContent)
            media = MediaIoBaseUpload(fh, fileMimeType, 1024 * 1024, resumable=True)
            body = {
                'title': self.fileName,
                'description': "",
                "parents": [{
                                "id" : self.folderId
                            }],
                'mimeType': fileMimeType
              }

        http = httplib2.Http()
        if credentials.invalid is True:
            credentials.refresh(http)
        else:
            http = credentials.authorize(http)

        drive_service = build('drive', 'v2', http=http)

        if self.action != EaseConstants.DELETE:
            if self.action == EaseConstants.CREATE:
                request = drive_service.files().insert(body=body, media_body=media)
            else:
                # self.action == EtelosConstants.UPDATE:
                if self.fileId != "":
                    request = drive_service.files().update(fileId=self.fileId, body=body, media_body=media)
                else:
                    request = drive_service.files().insert(body=body, media_body=media)
            response = None
            while response is None:
                status, response = request.next_chunk()
                if status:
                    print "Uploaded %d%%." % int(status.progress() * 100)
            resultObj = response
            webContentLinkWithExport = resultObj['webContentLink']
            fileId = resultObj['id']
            pos = webContentLinkWithExport.rfind("&export=")
            if pos > 0:
                webContentLink = webContentLinkWithExport[:pos]
            else:
                webContentLink = webContentLinkWithExport

            resultObj['isSuccess'] = True
            resultObj['id'] = fileId
            resultObj['link'] = webContentLink
        else:
            response = drive_service.files().delete(fileId=self.fileId).execute()
            if response == "":
                resultObj['isSuccess'] = True
            else:
                resultObj['isSuccess'] = False
                resultObj['error'] = "<div style='text-align: center'><h1>Delete Image Failed...</h1></div>"

        return resultObj


class Create(webapp2.RequestHandler):
    def post(self):
        GlobalCommonVars.requestHandler = self
        postData = self.request.POST
        postDataArr = self.request.POST.items()
        data = {}
        keyArray = []
        tableName = ""
        redirectURL = ""

        readAllCookies(self.request)

        for keyObj in postDataArr:
            key = keyObj[0]
            keyValue = keyObj[1]
            if key == "tableName":
                continue
            tableNameAndKeyArr = key.split(".")
            if len(tableNameAndKeyArr) > 1:
                firstValue = tableNameAndKeyArr[0]
                if firstValue in [EaseConstants.CREATE, EaseConstants.UPDATE, EaseConstants.DELETE]:
                    value = tableNameAndKeyArr[1]
                    if value == "redirect":
                        redirectURL = keyValue
                        continue
                elif firstValue == "cookie":
                    cookieKey = tableNameAndKeyArr[1]
                    cookieKeyValueArr = keyValue.split(".")
                    if cookieKeyValueArr[0] == "form":
                        cookieValue = ""
                        formKey = cookieKeyValueArr[1]
                        if formKey in postData:
                            cookieValue = postData[formKey]
                        elif (tableName + "." + formKey) in postData:
                            cookieValue = postData[(tableName + "." + formKey)]
                        GlobalCommonVars.cookie.setCookie(cookieKey, cookieValue)
                        continue
                elif firstValue in ["file"]:
                    folderId = tableNameAndKeyArr[1]
                    fileInputName = tableNameAndKeyArr[2]
                    if not keyValue is None and not keyValue == "":
                        fileUpload = UploadFileToGoogleDrive()
                        fileUpload.folderId = folderId
                        fileUpload.fileName = self.request.params[key].filename
                        fileUpload.fileContent = self.request.params[key].file.read()
                        fileUpload.action = EaseConstants.CREATE
                        uploadResult = fileUpload.uploadFile()
                        if uploadResult['isSuccess']:
                            data[fileInputName + "Id"] = uploadResult['id']
                            data[fileInputName] = uploadResult['link']
                        else:
                            # del GlobalCommonVars.fileUploadFolderIds[fileInputName]
                            self.response.write(uploadResult['error'])
                            return
                    else:
                        data[fileInputName] = ""
                        data[fileInputName + "Id"] = ""
                    keyArray.append(fileInputName)
                    keyArray.append(fileInputName + "Id")
                    # del GlobalCommonVars.fileUploadFolderIds[fileInputName]
                    continue
                else:
                    tableName = firstValue
                    if tableName not in data:
                        data["tableName"] = tableName
                    postDataKey = tableNameAndKeyArr[1]
                    data[postDataKey] = keyValue
                    keyArray.append(postDataKey)
            else:
                if key in [EaseConstants.CREATE, EaseConstants.UPDATE, EaseConstants.DELETE]:
                    continue
                else:
                    if key in data:
                        if not keyValue == "":
                            data[key] = keyValue
                    else:
                        data[key] = keyValue
                    if keyArray.count(key) <= 0:
                        keyArray.append(key)

        dbObj = datastore.Entity(kind=data["tableName"])

        if "id" not in data:
            md5Val = hashlib.md5()
            md5Val.update(tableName)
            md5Val.update(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            md5Val.update(str(random.random()))
            md5Val.update(str(random.random()))
            uId = md5Val.hexdigest()
            dbObj["id"] = uId
            data["id"] = uId

        for key in keyArray:
            try:
                if len(str(data[key])) > 500:
                    dbObj[key] = db.Text(data[key])
                else:
                    dbObj[key] = data[key]
            except:
                dbObj[key] = db.Text(data[key])
        datastore.Put(dbObj)

        global dataObj
        dataObj = data
        if EaseConstants.IMMEDIATELY in GlobalCommonVars.emails:
            for emailMessage in GlobalCommonVars.emails[EaseConstants.IMMEDIATELY]:
                sendEMailMessage(emailMessage)
                GlobalCommonVars.emails[EaseConstants.IMMEDIATELY].remove(emailMessage)

        if EaseConstants.CREATE in GlobalCommonVars.emails:
            for emailMessage in GlobalCommonVars.emails[EaseConstants.CREATE]:
                sendEMailMessage(emailMessage)
                GlobalCommonVars.emails[EaseConstants.CREATE].remove(emailMessage)

        redirectURL = re.sub(r'(?is)(.*?)<# form\.(.*?)#>(?is)', replFormValues, redirectURL)
        dataObj = {}

        GlobalCommonVars.requestHandler = {}
        writeAllCookies(self.response)

        if not redirectURL == "":
            redirectURL = redirectURL.replace("\"", "")
            self.redirect(str(redirectURL))
        else:
            self.redirect('/')


def sendEMailMessage(emailMessage):
    message = emailMessage["message"]
    bodyPageURL = emailMessage["bodyPage"]
    isHTML = emailMessage["html"]

    #message = mail.EmailMessage()
    message.to = re.sub(r'(?is)(.*?)<# form\.(.*?)#>(?is)', replFormValues, message.to)
    message.sender = re.sub(r'(?is)(.*?)<# form\.(.*?)#>(?is)', replFormValues, message.sender)
    try:
        message.cc = re.sub(r'(?is)(.*?)<# form\.(.*?)#>(?is)', replFormValues, message.cc)
    except:
        pass    # do nothing

    try:
        message.bcc = re.sub(r'(?is)(.*?)<# form\.(.*?)#>(?is)', replFormValues, message.cc)
    except:
        pass    # do nothing

    if len(bodyPageURL.strip()) > 0:
        bodyPageURL = re.sub(ease.easePatterns.systemTagsPattern, ease.easeCommon.replSystemTags, bodyPageURL)
        bodyPageURL = re.sub(r'(?is)(.*?)<# form\.(.*?)#>(?is)', replFormValues, bodyPageURL)
        emailBody = parseBodyPage(bodyPageURL)
    else:
        emailBody = message.body
        emailBody = re.sub(ease.easePatterns.urlReplacePattern, ease.easeCommon.replURL, emailBody)
        emailBody = re.sub(r'(?is)(.*?)<# form\.(.*?)#>(?is)', replFormValues, emailBody)
        emailBody = re.sub(ease.easePatterns.hashTagPattern, ease.easeCommon.replHashTagValue, emailBody)
    if isHTML is True:
        message.html = emailBody
    else:
        message.body = emailBody
    message.send()


class Update(webapp2.RequestHandler):
    def post(self):
        postData = self.request.POST
        postDataArr = self.request.POST.items()
        GlobalCommonVars.requestHandler = self
        data = {}
        keyArray = []
        data["tableName"] = ""
        action = ""
        redirectURLs = {}
        recordNeedToUpdate = None
        fileUploadsArr = []

        readAllCookies(self.request)

        for keyObj in postDataArr:
            key = keyObj[0]
            keyValue = keyObj[1]
            if key == "tableName":
                tableName = keyValue
                data["tableName"] = tableName
                dbObj = datastore.Query(tableName.strip(), {"id": self.request.get("id")})
                dbObj.Run()
                count = dbObj.Count()
                if count > 0:
                    recordsList = dbObj.Get(count)
                    recordNeedToUpdate = recordsList[0]
                continue
            elif key == EaseConstants.UPDATE:
                action = EaseConstants.UPDATE
                continue
            elif key == EaseConstants.DELETE:
                action = EaseConstants.DELETE
                continue
            tableNameAndKeyArr = key.split(".")
            if len(tableNameAndKeyArr) > 1:
                firstValue = tableNameAndKeyArr[0]
                if firstValue in [EaseConstants.CREATE, EaseConstants.UPDATE, EaseConstants.DELETE]:
                    value = tableNameAndKeyArr[1]
                    if value == "redirect":
                        redirectURLs[firstValue] = keyValue
                        continue
                elif firstValue == "cookie":
                    cookieKey = tableNameAndKeyArr[1]
                    cookieKeyValueArr = keyValue.split(".")
                    if cookieKeyValueArr[0] == "form":
                        cookieValue = ""
                        formKey = cookieKeyValueArr[1]
                        if formKey in postData:
                            cookieValue = postData[formKey]
                        elif (tableName + "." + formKey) in postData:
                            cookieValue = postData[(tableName + "." + formKey)]
                        GlobalCommonVars.cookie.setCookie(cookieKey, cookieValue)
                        continue
                elif firstValue in ["file"]:
                    folderId = tableNameAndKeyArr[1]
                    fileInputName = tableNameAndKeyArr[2]
                    if not keyValue is None or not keyValue == "":
                        fileUpload = UploadFileToGoogleDrive()
                        fileUpload.folderId = folderId
                        if self.request.params[key] != "":
                            fileUpload.fileName = self.request.params[key].filename
                            fileUpload.fileContent = self.request.params[key].file.read()
                            fileUpload.fileId = recordNeedToUpdate[fileInputName + "Id"]
                            fileUpload.inputName = fileInputName
                            fileUploadsArr.append(fileUpload)
                        # del GlobalCommonVars.fileUploadFolderIds[fileInputName]
                    continue
                else:
                    tableName = firstValue
                    if tableName not in data:
                        data["tableName"] = tableName
                    postDataKey = tableNameAndKeyArr[1]
                    data[postDataKey] = keyValue
                    keyArray.append(postDataKey)
            else:
                if key in data:
                    if not keyValue == "":
                        data[key] = keyValue
                else:
                    data[key] = keyValue
                if keyArray.count(key) <= 0:
                    keyArray.append(key)

        for fileUploadObj in fileUploadsArr:
            #fileUploadObj = UploadFileToGoogleDrive()
            fileUploadObj.action = action
            uploadResult = fileUploadObj.uploadFile()
            if action == EaseConstants.UPDATE:
                if uploadResult['isSuccess']:
                    data[fileUploadObj.inputName + "Id"] = uploadResult['id']
                    data[fileUploadObj.inputName] = uploadResult['link']
                    keyArray.append(fileUploadObj.inputName)
                    keyArray.append(fileUploadObj.inputName + "Id")
                else:
                    self.response.write(uploadResult['error'])
                    return

        if not recordNeedToUpdate is None:
            if action == EaseConstants.UPDATE:
                for key in keyArray:
                    if key == "id":
                        continue
                    if key in data:
                        try:
                            if len(str(data[key])) > 500:
                                recordNeedToUpdate[key] = db.Text(data[key])
                            else:
                                recordNeedToUpdate[key] = data[key]
                        except:
                            recordNeedToUpdate[key] = db.Text(data[key])
                    elif not key in recordNeedToUpdate:
                        recordNeedToUpdate[key] = ""
                datastore.Put(recordNeedToUpdate)
            else:
                datastore.Delete(recordNeedToUpdate)

        GlobalCommonVars.requestHandler = {}
        writeAllCookies(self.response)

        if len(redirectURLs) > 0:
            redirectURL = redirectURLs[action]
            global dataObj
            dataObj = data
            redirectURL = re.sub(r'(?is)(.*?)<# form\.(.*?)#>(?is)', replFormValues, redirectURL)
            dataObj = {}
            redirectURL = redirectURL.replace("\"", "")
            self.redirect(str(redirectURL))
        else:
            self.redirect('/')


class GDriveCredentials(db.Model):
    credentials = db.TextProperty()


def parseBodyPage(bodyPageURL):
    pageURLEndPos = bodyPageURL.rindex("?")
    pageBody = ""
    if pageURLEndPos != -1:
        pageURL = bodyPageURL[:pageURLEndPos]
        try:
            pathToEspx = os.path.join(os.path.split(__file__)[0], pageURL + '.espx')
            pageBodyContent = file(pathToEspx, 'r').read()
        except:
            pageBodyContent = ""
        if len(pageBodyContent.strip()) > 0:
            pageParamsStr = bodyPageURL[(pageURLEndPos + 1):]
            paramsArr = pageParamsStr.split("&")
            if len(paramsArr) > 0:
                for singleParamStr in paramsArr:
                    paramKeyValueArr = singleParamStr.split("=")
                    key = paramKeyValueArr[0].strip()
                    if len(key) > 0:
                        if len(paramKeyValueArr) > 1:
                            GlobalCommonVars.reqParams[key] = paramKeyValueArr[1]
                        else:
                            GlobalCommonVars.reqParams[key] = ""
            easeParserObj = ease.easeParser.EaseParser()
            easeParserObj.easeStr = pageBodyContent
            easeParserObj.parseEase()
            pageBody = easeParserObj.parsedStr
        else:
            pageBody = ""

    return pageBody


def replFormValues(m):
    formKeyName = m.group(2).strip()
    return m.group(1) + getFormValue(formKeyName)


def getFormValue(key):
    result = ""
    if key in dataObj:
        result = dataObj[key]
    return result


# class createSpreadSheet(webapp2.RequestHandler):
#     def post(self):
#         data = {}
#         keyArray = []
#
#         gSpreadsheetkey = self.request.get("key")
#         spreadsheetname = self.request.get("spreadsheetname")
#         rowno = int(self.request.get("rowno"))
#
#         #	    if tmpKey[0] not in ["key","email","password","spreadsheetname","rowno"]:
#
#         easeGAppCredentials = EaseGAppCredentials()
#         easeGAppCredentials.readCredentials()
#         if not easeGAppCredentials.isReadSuccess:
#             result = "<div style='text-align: center'><h1>Credentials not found...</h1></div>"
#             self.response.write(result)
#             return
#
#         gc = gspread.login(easeGAppCredentials.gSpreadSheetEmail, easeGAppCredentials.gSpreadSheetPassword)
#         spreadsheet = gc.open_by_key(gSpreadsheetkey)
#         worksheet = spreadsheet.worksheet(spreadsheetname)
#
#         for key in self.request.params:
#             if key in ["key", "spreadsheetname", "rowno"]:
#                 continue
#             elif key == "redirect":
#                 redirectURL = self.request.get(key)
#                 continue
#             tmpKey = key.split(".")
#             if len(tmpKey) > 1:
#                 if not tmpKey[0].strip() == "row":
#                     continue
#                 else:
#                     value = self.request.get(key)
#                     tmp = value.split(".")
#                     if len(tmp) > 1:
#                         if tmp[0] == "system" and tmp[1] == "date_time_short":
#                             value = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#                     if rowno == 0:
#                         rowno = worksheet.row_count + 1
#                         worksheet.resize(rowno)
#                     worksheet.update_acell(tmpKey[1].strip().upper() + str(rowno), value)
#         self.redirect('/')
#         # if GlobalCommonVars.isRedirect:
#         #     redirectURL = GlobalCommonVars.redirectURL
#         #     redirectURL = redirectURL.replace("\"", "")
#         #     self.redirect(redirectURL)
#         # else:
#         #     self.redirect('/')
#

class GSpreadSheet(webapp2.RequestHandler):
    def post(self):
        redirectURL = ""
        gSpreadSheetKey = self.request.get("key")
        gSpreadSheetName = self.request.get("gSpreadSheet")
        rowNo = self.request.get("rowNo")
        GlobalCommonVars.requestHandler = self
        easeGAppCredentials = EaseGAppCredentials()
        easeGAppCredentials.readCredentials()
        if not easeGAppCredentials.isReadSuccess:
            result = "<div style='text-align: center'><h1>Credentials not found...</h1></div>"
            self.response.write(result)
            return

        gc = gspread.login(easeGAppCredentials.gSpreadSheetEmail, easeGAppCredentials.gSpreadSheetPassword)
        spreadsheet = gc.open_by_key(gSpreadSheetKey)
        worksheet = spreadsheet.worksheet(gSpreadSheetName)
        action = ""

        for key in self.request.params:
            if key in ["key", "gSpreadSheet", "rowNo"]:
                continue
            elif key == "action":
                action = self.request.get(key)
                continue
            elif key in [EaseConstants.CREATE, EaseConstants.UPDATE, EaseConstants.DELETE]:
                action = key
                continue
            tmpKey = key.split(".")
            rowName = ""
            if len(tmpKey) > 1:
                firstValue = tmpKey[0]
                if firstValue in [EaseConstants.CREATE, EaseConstants.UPDATE, EaseConstants.DELETE]:
                    secondValue = tmpKey[1]
                    if secondValue == "redirect":
                        redirectURL = self.request.get(key)
                        continue
                elif tmpKey[0].strip() == "row":
                    rowName = tmpKey[1].strip()
            else:
                rowName = tmpKey[0]
            value = self.request.get(key)
            if rowNo == 0 or rowNo == "":
                rowNo = worksheet.row_count + 1
                worksheet.resize(rowNo)
            worksheet.update_acell(rowName.upper() + str(rowNo), value)
            # elif self.request.params['action'] == 'delete':
            #     worksheet.update_acell(tmpKey[1].strip().upper() + str(rowNo), value)

        GlobalCommonVars.requestHandler = {}

        if not redirectURL == "":
            redirectURL = redirectURL.replace("\"", "")
            self.redirect(str(redirectURL))
        else:
            self.redirect('/')


# class printGoogleDoc(webapp2.RequestHandler):
#     def get(self):
#         result = ''
#
#         fileId = self.request.get('fileId')
#         authCode = self.request.get('code')
#
#         credentials = None
#
#         credentials = get_stored_credentials()
#
#         # q = MyCredentialsEntity.all()
#         # if q.count() > 0:
#         #     items = q.fetch(1)
#         #     obj = items.pop()
#         #     if not obj is None:
#         #         credentials = AccessTokenCredentials(obj.access_token, obj.user_agent)
#
#         if credentials is None and authCode == '':
#             authorize_url = self.get_auth_url(fileId)
#             self.redirect(str(authorize_url))
#             return
#         elif len(authCode) > 0 and credentials is None:
#             flow = self.get_flow(fileId)
#             credentials = flow.step2_exchange(authCode)
#             dbObj = MyCredentialsEntity()
#             if not credentials.access_token is None:
#                 dbObj.access_token = credentials.access_token
#             else:
#                 dbObj.access_token = ""
#             if not credentials.user_agent is None:
#                 dbObj.user_agent = credentials.user_agent
#             else:
#                 dbObj.user_agent = ""
#             dbObj.put()
#             if credentials.access_token_expired is True:
#                 logging.info('token is expired')
#                 result += "token expired"
#                 self.response.write(result)
#                 return
#             else:
#                 logging.info('token is not expired')
#                 result += "token not expired"
#                 http = self.get_authorize(credentials)
#         else:
#             http = self.get_authorize(credentials)
#
#         headers = {}
#         headers['Authorization'] = 'Bearer ' + credentials.access_token
#         #       credentials.apply(headers)
#         drive_service = build('drive', 'v2', http=http)
#
#         f = drive_service.files().get(fileId=fileId).execute()
#         alternateLink = f.get('alternateLink')
#         res = alternateLink.find('docs.google.com/document')
#         if res < 0:
#             result += alternateLink
#         else:
#             result += self.get_content_for_drive_file(drive_service, f)
#
#         result += "\n\n\n" + credentials.access_token + "\n\n"
#
#         self.response.write(result)
#
#     def get_authorize(self, credentials):
#         try:
#             http = httplib2.Http()
#             if credentials.invalid is True:
#                 credentials.refresh(http)
#             else:
#                 http = credentials.authorize(http)
#             return http
#         except AccessTokenCredentialsError(), error:
#             logging.error("Error :: %s", error)
#
#     def get_content_for_drive_file(self, drive_service, f):
#         result = ''
#         downloadURL = f.get('downloadUrl')
#         resp, content = drive_service._http.request(downloadURL)
#         if resp.status == 200:
#             result = content
#         return result
#
#     def get_content_for_doc_file(self, drive_service, f):
#         result = ''
#         exportLinks = f.get('alternateLink')
#         downloadURL = exportLinks['text/plain']
#         resp, content = drive_service._http.request(exportLinks)
#
#         return str(result)
#
#     def get_auth_url(self, fileId):
#         flow = self.get_flow(fileId)
#         authorize_url = flow.step1_get_authorize_url()
#         return authorize_url
#
#     def get_flow(self, fileId):
#         flow = OAuth2WebServerFlow(client_id=GlobalCommonVars.CLIENT_ID, client_secret=GlobalCommonVars.CLIENT_SECRET, scope=GlobalCommonVars.OAUTH_SCOPE,
#                                    redirect_uri=GlobalCommonVars.REDIRECT_URI)
#         flow.redirect_uri = GlobalCommonVars.REDIRECT_URI
#         return flow


class GenerateAccessToken(webapp2.RequestHandler):
    def get(self):
        redirectURL = self.request.get("redirectURL")
        GlobalCommonVars.requestHandler = self
        GlobalCommonVars.currSession = get_current_session()
        GlobalCommonVars.currSession['easeTokenRedirectURL'] = redirectURL
        easeGAppCredentials = EaseGAppCredentials()
        easeGAppCredentials.readCredentials()
        if easeGAppCredentials.isReadSuccess:
            authorize_url = get_authorization_url('clwdease@gmail.com', "accessToken", easeGAppCredentials)
            GlobalCommonVars.requestHandler = {}
            self.redirect(str(authorize_url))
        else:
            result = "<div style='text-align: center'><h1>Credentials not found...</h1></div>"
            self.response.write(result)


class HandleAccessToken(webapp2.RedirectHandler):
    def get(self):
        result = ""
        code = self.request.get("code")
        GlobalCommonVars.requestHandler = self
        if len(code) > 0:
            easeGAppCredentials = EaseGAppCredentials()
            easeGAppCredentials.readCredentials()
            if easeGAppCredentials.isReadSuccess:
                credentials = exchange_code(code, easeGAppCredentials)
                if not credentials.invalid:
                    store_credentials(credentials)

                GlobalCommonVars.currSession = get_current_session()
                redirectURL = GlobalCommonVars.currSession['easeTokenRedirectURL']
                self.redirect(str(redirectURL))
            else:
                result = "<div style='text-align: center'><h1>Credentials not found...</h1></div>"
                self.response.write(result)
        else:
            result = "<h1>Code not found</h1>"

        GlobalCommonVars.requestHandler = {}
        self.response.write(result)


def get_authorization_url(email_address, state, easeGAppCredentials):
    flow = OAuth2WebServerFlow(client_id=easeGAppCredentials.gAppClientID, client_secret=easeGAppCredentials.gAppSecret,
                               scope=GlobalCommonVars.OAUTH_SCOPE, redirect_uri=easeGAppCredentials.gAppRedirectURI)
    flow.redirect_uri = easeGAppCredentials.gAppRedirectURI
    flow.params['approval_prompt'] = 'auto'
    flow.params['user_id'] = easeGAppCredentials.gSpreadSheetEmail
    flow.params['state'] = state
    return flow.step1_get_authorize_url(easeGAppCredentials.gAppRedirectURI)


def exchange_code(authorization_code, easeGAppCredentials):
    flow = OAuth2WebServerFlow(client_id=easeGAppCredentials.gAppClientID, client_secret=easeGAppCredentials.gAppSecret,
                               scope=GlobalCommonVars.OAUTH_SCOPE, redirect_uri=easeGAppCredentials.gAppRedirectURI)
    flow.redirect_uri = easeGAppCredentials.gAppRedirectURI
    try:
        credentials = flow.step2_exchange(authorization_code)
        return credentials
    except FlowExchangeError, error:
        logging.error('An error occurred: %s', error)


def store_credentials(credentials):
    dbObj = GDriveCredentials.all(keys_only=True)
    entries = dbObj.fetch(dbObj.count())
    db.delete(entries)
    newDBObj = GDriveCredentials()
    newDBObj.credentials = credentials.to_json()
    newDBObj.put()

    print credentials.to_json()


def get_stored_credentials():
    q = GDriveCredentials.all()
    credentials = None
    if q.count() > 0:
        items = q.fetch(1)
        obj = items.pop()
        if not obj is None:
            credentials = Credentials.new_from_json(obj.credentials)
            if credentials.invalid:
                http = credentials.authorize(httplib2.Http())
                credentials.refresh(http)

    return credentials


def writeAllCookies(responseObj):
    for key in GlobalCommonVars.cookie.c:
        expires = GlobalCommonVars.cookie.c[key]["expires"]
        if not expires == "":
            responseObj.set_cookie(str(key), GlobalCommonVars.cookie.getCookie(key), expires=expires)
        else:
            responseObj.set_cookie(str(key), GlobalCommonVars.cookie.getCookie(key))


def readAllCookies(requestObj):
    requestCookies = requestObj.cookies
    GlobalCommonVars.cookie = ease.cookies.cookie()
    GlobalCommonVars.cookie.clearAll()
    for key in requestCookies:
        GlobalCommonVars.cookie.setCookie(str(key), requestCookies.get(key))


class MainHandler(webapp2.RequestHandler):
    def get(self):

        GlobalCommonVars.requestHandler = self
        GlobalCommonVars.emails = {}
        GlobalCommonVars.currSession = get_current_session()

        # get all cookies from request and set them into our cookie class
        readAllCookies(self.request)

        # requestCookies = self.request.cookies
        # GlobalCommonVars.cookie = ease.cookies.cookie()
        # GlobalCommonVars.cookie.clearAll()
        # for key in requestCookies:
        #     GlobalCommonVars.cookie.setCookie(str(key), requestCookies.get(key))

        result = ''
        GlobalCommonVars.formAction = ""
        pageRequested = self.request.get("page").strip()
        if pageRequested == "":
            pageRequested = "index"
        #ease.etelosCommon.init()
        GlobalCommonVars.reqParams = {}
        for key in self.request.params:
            GlobalCommonVars.reqParams[key] = self.request.get(key)
        try:
            pathToEspx = os.path.join(os.path.split(__file__)[0], pageRequested + '.espx')
            espxCode = file(pathToEspx, 'r').read()
        except:
            #ease.etelosCommon.session.terminate(clear_data=True)
            self.response.write("<div style='text-align: center'><h1>404 Page Not Found</h1></div>")
            return
            # magic starts here
        easeParserObj = ease.easeParser.EaseParser()
        easeParserObj.easeStr = espxCode
        easeParserObj.parseEase()
        finalHTML = easeParserObj.parsedStr

        # easeParserObj = ease.parser.Parser()
        # finalHTML = easeParserObj.parse(espxCode)
        # parse out espxCode to make forms and lists process or apply tags
        # ease_parser.py --- this is the main parser...
        # should we organize all these into a sub folder?
        # magic ends here
        if len(GlobalCommonVars.functionRecords) > 0:
            self.processRecords()

        global dataObj
        dataObj = {}
        if EaseConstants.IMMEDIATELY in GlobalCommonVars.emails:
            for emailMessage in GlobalCommonVars.emails[EaseConstants.IMMEDIATELY]:
                sendEMailMessage(emailMessage)
                GlobalCommonVars.emails[EaseConstants.IMMEDIATELY].remove(emailMessage)

        dataObj = {}

        # if GlobalCommonVars.isRedirect:
        #     redirectURL = GlobalCommonVars.redirectURL
        #     redirectURL = redirectURL.replace("\"", "")
        #     self.redirect(redirectURL)

        result += finalHTML
        GlobalCommonVars.requestHandler = {}

        # write all cookies in response

        writeAllCookies(self.response)

        # for key in GlobalCommonVars.cookie.c:
        #     expires = GlobalCommonVars.cookie.c[key]["expires"]
        #     if not expires == "":
        #         self.response.set_cookie(str(key), GlobalCommonVars.cookie.getCookie(key), expires=expires)
        #     else:
        #         self.response.set_cookie(str(key), GlobalCommonVars.cookie.getCookie(key))

        self.response.write(result)

    def processRecords(self):
        result = ""
        for record in GlobalCommonVars.functionRecords:
            if record.isGSpreadRecord:
                result += self.processGSpreadRecord(record)
            else:
                result += self.processFormRecord(record)

            if GlobalCommonVars.parameters.has_key(record.refName):
                del GlobalCommonVars.parameters[record.refName]

        GlobalCommonVars.functionRecords = []
        return result

    def processFormRecord(self, record):
        result = ""
        if record.operation == EaseConstants.CREATE_NEW_RECORD:
            record.record = GlobalCommonVars.parameters[record.refName]
            dbObj = datastore.Entity(kind=record.tableName)

            for key in record.record:
                try:
                    if len(str(record.record[key])) > 500:
                        dbObj[key] = db.Text(record.record[key])
                    else:
                        dbObj[key] = record.record[key]
                except:
                    dbObj[key] = db.Text(record.record[key])
            datastore.Put(dbObj)
        elif record.operation == EaseConstants.UPDATE_NEW_RECORD:
            record.record = GlobalCommonVars.parameters[record.refName]
            dbObj = datastore.Query(record.tableName.strip(), {"id": record.record["id"]})
            dbObj.Run()
            count = dbObj.Count()
            if count > 0:
                recordsList = dbObj.Get(count)
                currRecord = recordsList[0]
                for key in record.record:
                    try:
                        if len(str(record.record[key])) > 500:
                            currRecord[key] = db.Text(record.record[key])
                        else:
                            currRecord[key] = record.record[key]
                    except:
                        currRecord[key] = db.Text(record.record[key])
                datastore.Put(currRecord)

        return result

    def processGSpreadRecord(self, record):
        result = ""
        easeGAppCredentials = EaseGAppCredentials()
        easeGAppCredentials.readCredentials()
        if not easeGAppCredentials.isReadSuccess:
            result = "<div style='text-align: center'><h1>Credentials not found to insert record...</h1></div>"
            return result

        gc = gspread.login(easeGAppCredentials.gSpreadSheetEmail, easeGAppCredentials.gSpreadSheetPassword)
        spreadsheet = gc.open_by_key(record.tableName)
        worksheet = spreadsheet.worksheet(record.sheetName)
        rowNo = 0

        if record.operation == EaseConstants.CREATE_NEW_RECORD:
            record.record = GlobalCommonVars.parameters[record.refName]
            for key in record.record:
                value = record.record[key]
                if rowNo == 0 or rowNo == "":
                    rowNo = worksheet.row_count + 1
                    worksheet.resize(rowNo)
                worksheet.update_acell(key.upper() + str(rowNo), value)

        return result

config = {}

config['webapp2_extras.sessions'] = {
    'secret_key': 'my-super-secret-key',
}

app = webapp2.WSGIApplication([
                                  ('/', MainHandler),
                                  ('/create', Create),
                                  ('/createInGSpreadsheet', GSpreadSheet),
                                  ('/updateinspreadsheet', GSpreadSheet),
                                  ('/update', Update),
                                  ('/genrateAccessToken', GenerateAccessToken),
                                  ('/handleAccessToken', HandleAccessToken),
                                  # ('/printgoogledoc', printGoogleDoc),
                                  # ('/googleDocUpload', googleDocUpload),
                                  # ('/googleFileUpload', GoogleFileUpload),
                                  # ('/sendEmail', sendEmail),
                                  # ('/testUpdate', testUpdate),
                              ], debug=True, config=config)
