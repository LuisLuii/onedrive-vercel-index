import { posix as pathPosix } from 'path'

import type { NextApiRequest, NextApiResponse } from 'next'
import axios from 'axios'
import Cors from 'cors'


import { driveApi, cacheControlHeader, graphApi } from '../../config/api.config'
import { encodePath, getAccessToken, checkAuthRoute } from '.'

// CORS middleware for raw links: https://nextjs.org/docs/api-routes/api-middlewares
export function runCorsMiddleware(req: NextApiRequest, res: NextApiResponse) {
  const cors = Cors({ methods: ['GET', 'HEAD'] })
  return new Promise((resolve, reject) => {
    cors(req, res, result => {
      if (result instanceof Error) {
        return reject(result)
      }

      return resolve(result)
    })
  })
}


const replaceUrl = function(url) {
  if (!url){
    return url
  }
  let dns = process.env.DNS_URL || ''
  let domain: any = (new URL(url));
  domain = domain.hostname;
  if (dns){
    return url.replace(domain, dns)
  }else{
    url
  }

}




async function getContentWithHeaders(url, headers) {
  const folderData = await axios.get(url, {
    headers: headers,
    params: {
      expand: `children(select=name,size,parentReference,lastModifiedDateTime,@microsoft.graph.downloadUrl,remoteItem,file,video,image)`,
    },
    
  })
  // const result = await gatherResponse(folderData);
  return folderData.data;
}


export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const accessToken = await getAccessToken()
  if (!accessToken) {
    res.status(403).json({ error: 'No access token.' })
    return
  }

  const { path = '/', odpt = '', proxy = false } = req.query

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
  const cleanPath = pathPosix.resolve('/', pathPosix.normalize(path))

  // Handle protected routes authentication
  const odTokenHeader = (req.headers['od-protected-token'] as string) ?? odpt

  const { code, message } = await checkAuthRoute(cleanPath, accessToken, odTokenHeader)
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

  await runCorsMiddleware(req, res)
    

  let paths = cleanPath.split('/').filter(n => n)
    if (paths.length === 0) {
      paths = [""]
    }

  let body: any = null

  let isSharedFolder = false
  let sharedPath = ""
  let normalPath = ""
  for (let levlelPath in paths) {
    
    if ((!normalPath && !sharedPath) && (paths[levlelPath])) paths[levlelPath] = ":/" + paths[levlelPath];
    let uri
    if (!isSharedFolder) {
      let tempPath = paths[levlelPath]
      if (normalPath) {
        tempPath = ":" + normalPath + "/" + paths[levlelPath]
      }
      uri =
      graphApi + 
      "/v1.0/me/drive/root" +
      encodeURI(tempPath) ;
      body = await getContentWithHeaders(uri, {
        Authorization: "Bearer " + accessToken,
      });

    } else {
      let tempPath =  sharedPath  + "/" + paths[levlelPath] 
      uri = graphApi + "/v1.0" + encodeURI(tempPath);
      body = await getContentWithHeaders(uri, {
        Authorization: "Bearer " + accessToken,
      });
    }
    
    if (body && body.remoteItem) {
      isSharedFolder = true
      const rDId = body.remoteItem.parentReference.driveId
      const rId = body.remoteItem.id
      uri = graphApi + "/v1.0/drives/" + rDId + "/items/" + rId;
      body = await getContentWithHeaders(uri, {
        Authorization: "Bearer " + accessToken,
      });
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
    if ('@microsoft.graph.downloadUrl' in body) {
      // Only proxy raw file content response for files up to 4MB
      if (proxy && 'size' in body && body['size'] < 4194304) {
        const { headers, data: stream } = await axios.get(replaceUrl(body['@microsoft.graph.downloadUrl']) as string, {
          responseType: 'stream',
        })
        headers['Cache-Control'] = cacheControlHeader
        // Send data stream as response
        res.writeHead(200, headers)
        stream.pipe(res)
      } else {
        res.redirect(replaceUrl(body['@microsoft.graph.downloadUrl']))
      }
    } else {
      res.status(404).json({ error: 'No download url found.' })
    }
    return 
  
}
