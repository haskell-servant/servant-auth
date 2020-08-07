module Servant.Auth.Server.Internal.CachedRequest where

data RequestCacher = RequestCacher
  { expiresAt :: MVar UTCTime
  , currentValue :: MVar JWKSet
  , requestUrl :: String
  }

-- |
getCacheValue :: RequestCacher a -> IO a
getCacheValue cacher = do
  now <- getCurrentTime
  expiration <- readMVar $ expiresAt cacher
  if expiration < now
    then
    else


newRequestCacher :: String -> IO RequestCacher
newRequestCacher url = do
  mgr <- newManager defaultManagerSettings
  request <- parseUrlThrow url
