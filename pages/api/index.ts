import { posix as pathPosix } from 'path'

import type { NextApiRequest, NextApiResponse } from 'next'
import axios from 'axios'

import apiConfig from '../../config/api.config'
import siteConfig from '../../config/site.config'
import { revealObfuscatedToken } from '../../utils/oAuthHandler'
import { compareHashedToken } from '../../utils/protectedRouteHandler'
import { getOdAuthTokens, storeOdAuthTokens } from '../../utils/odAuthTokenStore'
import { runCorsMiddleware } from './raw' 

const basePath = pathPosix.resolve('/', siteConfig.baseDirectory)
const clientSecret = revealObfuscatedToken(apiConfig.obfuscatedClientSecret)

/**
 * Encode the path of the file relative to the base directory
 *
 * @param path Relative path of the file to the base directory
 * @returns Absolute path of the file inside OneDrive
 */
export function encodePath(path: string): string {
  let encodedPath = pathPosix.join(basePath, path)
  if (encodedPath === '/' || encodedPath === '') {
    return ''
  }
  encodedPath = encodedPath.replace(/\/$/, '')
  return `:${encodeURIComponent(encodedPath)}`
}

/**
 * Fetch the access token from Redis storage and check if the token requires a renew
 *
 * @returns Access token for OneDrive API
 */
export async function getAccessToken(): Promise<string> {
  const { accessToken, refreshToken } = await getOdAuthTokens()

  // Return in storage access token if it is still valid
  if (typeof accessToken === 'string') {
    console.log('Fetch access token from storage.')
    return accessToken
  }

  // Return empty string if no refresh token is stored, which requires the application to be re-authenticated
  if (typeof refreshToken !== 'string') {
    console.log('No refresh token, return empty access token.')
    return ''
  }

  // Fetch new access token with in storage refresh token
  const body = new URLSearchParams()
  body.append('client_id', apiConfig.clientId)
  body.append('redirect_uri', apiConfig.redirectUri)
  body.append('client_secret', clientSecret)
  body.append('refresh_token', refreshToken)
  body.append('grant_type', 'refresh_token')

  const resp = await axios.post(apiConfig.authApi, body, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  })

  if ('access_token' in resp.data && 'refresh_token' in resp.data) {
    const { expires_in, access_token, refresh_token } = resp.data
    await storeOdAuthTokens({
      accessToken: access_token,
      accessTokenExpiry: parseInt(expires_in),
      refreshToken: refresh_token,
    })
    console.log('Fetch new access token with stored refresh token.')
    return access_token
  }

  return ''
}

/**
 * Match protected routes in site config to get path to required auth token
 * @param path Path cleaned in advance
 * @returns Path to required auth token. If not required, return empty string.
 */
export function getAuthTokenPath(path: string) {
  // Ensure trailing slashes to compare paths component by component. Same for protectedRoutes.
  // Since OneDrive ignores case, lower case before comparing. Same for protectedRoutes.
  path = path.toLowerCase() + '/'
  const protectedRoutes = siteConfig.protectedRoutes as string[]
  let authTokenPath = ''
  for (let r of protectedRoutes) {
    if (typeof r !== 'string') continue
    r = r.toLowerCase().replace(/\/$/, '') + '/'
    if (path.startsWith(r)) {
      authTokenPath = `${r}.password`
      break
    }
  }
  return authTokenPath
}

/**
 * Handles protected route authentication:
 * - Match the cleanPath against an array of user defined protected routes
 * - If a match is found:
 * - 1. Download the .password file stored inside the protected route and parse its contents
 * - 2. Check if the od-protected-token header is present in the request
 * - The request is continued only if these two contents are exactly the same
 *
 * @param cleanPath Sanitised directory path, used for matching whether route is protected
 * @param accessToken OneDrive API access token
 * @param req Next.js request object
 * @param res Next.js response object
 */
export async function checkAuthRoute(
  cleanPath: string,
  accessToken: string,
  odTokenHeader: string
): Promise<{ code: 200 | 401 | 404 | 500; message: string }> {
  // Handle authentication through .password
  const authTokenPath = getAuthTokenPath(cleanPath)

  // Fetch password from remote file content
  if (authTokenPath === '') {
    return { code: 200, message: '' }
  }

  try {
    const token = await axios.get(`${apiConfig.driveApi}/root${encodePath(authTokenPath)}`, {
      headers: { Authorization: `Bearer ${accessToken}` },
      params: {
        select: '@microsoft.graph.downloadUrl,file',
      },
    })

    // Handle request and check for header 'od-protected-token'
    const odProtectedToken = await axios.get(token.data['@microsoft.graph.downloadUrl'])

    if (
      !compareHashedToken({
        odTokenHeader: odTokenHeader,
        dotPassword: odProtectedToken.data.toString(),
      })
    ) {
      return { code: 401, message: 'Password required.' }
    }
  } catch (error: any) {
    // Password file not found, fallback to 404
    if (error?.response?.status === 404) {
      return { code: 404, message: "You didn't set a password." }
    } else {
      return { code: 500, message: 'Internal server error.' }
    }
  }

  return { code: 200, message: 'Authenticated.' }
}


async function gatherResponse(response) {
  const { headers } = response;
  const contentType = headers.get("content-type");
  if (contentType.includes("application/json")) {
    return await response.data.json();
  } else if (contentType.includes("application/text")) {
    return await response.text();
  } else if (contentType.includes("text/html")) {
    return await response.text();
  } else {
    return await response.text();
  }
}

async function getContentWithHeaders(url, headers, next, sort) {
  const folderData = await axios.get(url, {
    headers: headers,
    params: {
      expand: `children(select=name,size,parentReference,lastModifiedDateTime,@microsoft.graph.downloadUrl,remoteItem,file,video,image;$top=${siteConfig.maxItems}${next && `';$skipToken='${next}`}${sort && `';$orderby='${sort}`} )`,
    },
    
  })
  // const result = await gatherResponse(folderData);
  return folderData.data;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  // If method is POST, then the API is called by the client to store acquired tokens
  if (req.method === 'POST') {
    const { obfuscatedAccessToken, accessTokenExpiry, obfuscatedRefreshToken } = req.body
    const accessToken = revealObfuscatedToken(obfuscatedAccessToken)
    const refreshToken = revealObfuscatedToken(obfuscatedRefreshToken)
    
    if (typeof accessToken !== 'string' || typeof refreshToken !== 'string') {
      res.status(400).send('Invalid request body')
      return
    }

    await storeOdAuthTokens({ accessToken, accessTokenExpiry, refreshToken })
    res.status(200).send('OK')
    return
  }

  // If method is GET, then the API is a normal request to the OneDrive API for files or folders
  const { path = '/', raw = false, next = '', sort = '' } = req.query
  // Set edge function caching for faster load times, check docs:
  // https://vercel.com/docs/concepts/functions/edge-caching
  res.setHeader('Cache-Control', apiConfig.cacheControlHeader)
  // Sometimes the path parameter is defaulted to '[...path]' which we need to handle
  if (path === '[...path]') {
    res.status(400).json({ error: 'No path specified.' })
    return
  }
  // If the path is not a valid path, return 400
  if (typeof path !== 'string') {
    res.status(400).json({ error: 'Path query invalid.' })
    return
  }
  // Besides normalizing and making absolute, trailing slashes are trimmed
  const cleanPath = pathPosix.resolve('/', pathPosix.normalize(path)).replace(/\/$/, '')
  // Validate sort param
  if (typeof sort !== 'string') {
    res.status(400).json({ error: 'Sort query invalid.' })
    return
  }
  const accessToken = await getAccessToken()
  // Return error 403 if access_token is empty
  if (!accessToken) {
    res.status(403).json({ error: 'No access token.' })
    return
  }

  // Handle protected routes authentication
  const { code, message } = await checkAuthRoute(cleanPath, accessToken, req.headers['od-protected-token'] as string)

  // Status code other than 200 means user has not authenticated yet
  if (code !== 200) {
    res.status(code).json({ error: message })
    return
  }

  // If message is empty, then the path is not protected.
  // Conversely, protected routes are not allowed to serve from cache.
  if (message !== '') {
    res.setHeader('Cache-Control', 'no-cache')
  }

  const requestPath = encodePath(cleanPath)
  // Handle response from OneDrive API
  const requestUrl = `${apiConfig.driveApi}/root${requestPath}`
  // Whether path is root, which requires some special treatment
  const isRoot = requestPath === ''

  try {

  let paths = path.split('/').filter(n => n)
  if (paths.length === 0) {
    paths = [""]
  }
  
  let body: any = null

  let isSharedFolder = false
  let sharedPath = ""
  let normalPath = ""
  console.log("1")
  for (let levlelPath in paths) {
    
    if ((!normalPath && !sharedPath) && (paths[levlelPath])) paths[levlelPath] = ":/" + paths[levlelPath];
    let uri
    if (!isSharedFolder) {
      let tempPath = paths[levlelPath]
      if (normalPath) {
        tempPath = ":" + normalPath + "/" + paths[levlelPath]
      }
      uri =
      apiConfig.graphApi + 
      "/v1.0/me/drive/root" +
      encodeURI(tempPath) ;
      body = await getContentWithHeaders(uri, {
        Authorization: "Bearer " + accessToken,
      }, next, sort);

    } else {
      let tempPath =  sharedPath  + "/" + paths[levlelPath] 
      uri = apiConfig.graphApi + "/v1.0" + encodeURI(tempPath);
      body = await getContentWithHeaders(uri, {
        Authorization: "Bearer " + accessToken,
      }, next, sort);
    }
    
    if (body && body.remoteItem) {
      isSharedFolder = true
      const rDId = body.remoteItem.parentReference.driveId
      const rId = body.remoteItem.id
      uri = apiConfig.graphApi + "/v1.0/drives/" + rDId + "/items/" + rId;
      body = await getContentWithHeaders(uri, {
        Authorization: "Bearer " + accessToken,
      }, next, sort);
      if (body && body.children && body.children.length > 0) {


        sharedPath = sharedPath + body.children[0].parentReference.path
        sharedPath = decodeURI(sharedPath)
        
      }
    }else{
      if (body && body.children && body.children[0] && body.children[0].parentReference&&body.children[0].parentReference.path  ){
        if (!isSharedFolder){
          normalPath = normalPath + body.children[0].parentReference&&body.children[0].parentReference.path.split(":")[1]
          normalPath = decodeURI(normalPath)
        } else {
          sharedPath = sharedPath + (body.children[0].parentReference && body.children[0].parentReference.path.split(":")[1])
          sharedPath = decodeURI(sharedPath)
          
        }
      }
    }
  }















  // Go for file raw download link, add CORS headers, and redirect to @microsoft.graph.downloadUrl
  // (kept here for backwards compatibility, and cache headers will be reverted to no-cache)
  


  if (raw) {
    console.log("rrrr")
    await runCorsMiddleware(req, res)
    res.setHeader('Cache-Control', 'no-cache')

    const { data } = await axios.get(requestUrl, {
      headers: { Authorization: `Bearer ${accessToken}` },
      params: {
        // OneDrive international version fails when only selecting the downloadUrl (what a stupid bug)
        select: 'id,@microsoft.graph.downloadUrl',
      },
    })

    if ('@microsoft.graph.downloadUrl' in data) {
      res.redirect(data['@microsoft.graph.downloadUrl'])
    } else {
      res.status(404).json({ error: 'No download url found.' })
    }
    return
  }


  // Querying current path identity (file or folder) and follow up query childrens in folder

  try {
    let resData: any = {}
    let files: any = [];
    let sharedfiles: any = [];
    let isFolder = true
    if ("file" in body) {
      resData = {
        "@odata.context": body['@odata.context'],
        name: body.name,
        size: body.size,
        lastModifiedDateTime: body.lastModifiedDateTime,
        id: body.id,
        file: body.file
      }
      isFolder = false
    } else {
      for (let i = 0; i < body.children.length; i++) {
        const file = body.children[i];
        if (file.remoteItem) {
          const remoteItemDriveId = file.remoteItem.parentReference.driveId
          const retrieveShareFileUri = apiConfig.graphApi + "/v1.0/drives/" + remoteItemDriveId + "/root" + "?expand=children(select=name,size,parentReference,lastModifiedDateTime,@microsoft.graph.downloadUrl,remoteItem)";
          const sharedFolderResBody = await getContentWithHeaders(retrieveShareFileUri, {
            Authorization: "Bearer " + accessToken,
          }, next, sort);
          for (let i = 0; i < sharedFolderResBody.children.length; i++) {
            const sharedFile = sharedFolderResBody.children[i];
            sharedfiles.push({
              name: sharedFile.name,
              size: sharedFile.size,
              lastModifiedDateTime: sharedFile.lastModifiedDateTime,
              id: sharedFile.id
            });
          }
          
        } else {
          files.push({
            name: file.name,
            size: file.size,
            lastModifiedDateTime: file.lastModifiedDateTime,
            id: file.id
          });
        }
      }

      const allFiles = [...files, ...sharedfiles]
      resData = {
        "@odata.context": body['@odata.context'],
        '@odata.count': allFiles.length,
        'value': allFiles
      }
    }

    // Extract next page token from full @odata.nextLink
    const nextPage = resData['@odata.nextLink']
      ? resData['@odata.nextLink'].match(/&\$skiptoken=(.+)/i)[1]
      : null
    // Return paging token if specified
    if (!isFolder) {
      res.status(200).json({ file: resData })
    }
    if (nextPage) {

        res.status(200).json({ folder: resData, next: nextPage })
    } else {
        res.status(200).json({ folder: resData })
    }
    return
  
  } catch (error: any) {
    res.status(error?.response?.code ?? 500).json({ error: error?.response?.data ?? 'Internal server error.' })
    return
  }
  } catch (error) {
    
    res.status(200).json({ error: error })
  }
}
