# servant-auth

[![Build Status](https://travis-ci.org/plow-technologies/servant-auth.svg?branch=master)](https://travis-ci.org/plow-technologies/servant-auth)

This package provides safe and easy-to-use authentication options for
`servant`. The same API can be protected via login and cookies, or API tokens,
without much extra work.


## How it works

This library introduces a combinator `Auth`:

~~~ {.haskell ignore}
Auth (auths :: [*]) val
~~~

What `Auth [Auth1, Auth2] Something :> API` means is that `API` is protected by
*either* `Auth1` *or* `Auth2`, and the result of authentication will be of type
`AuthResult Something`, where :

~~~ {.haskell ignore}
data AuthResult val
  = BadPassword
  | NoSuchUser
  | Authenticated val
  | Indefinite
~~~

Your handlers will get a value of type `AuthResult Something`, and can decide
what to do with it.

~~~ {.haskell}
{-# OPTIONS_GHC -fno-warn-unused-binds #-}
{-# OPTIONS_GHC -fno-warn-deprecations #-}
import Control.Concurrent (forkIO)
import Control.Monad (forever)
import Control.Monad.Trans (liftIO)
import Data.Aeson (FromJSON, ToJSON)
import GHC.Generics (Generic)
import Network.Wai.Handler.Warp (run)
import System.Environment (getArgs)
import Servant
import Servant.Auth.Server
import Servant.Auth.Server.SetCookieOrphan ()

data User = User { name :: String, email :: String }
   deriving (Eq, Show, Read, Generic)

instance ToJSON User
instance ToJWT User
instance FromJSON User
instance FromJWT User

data Login = Login { username :: String, password :: String }
   deriving (Eq, Show, Read, Generic)

instance ToJSON Login
instance FromJSON Login

type Protected
   = "name" :> Get '[JSON] String
 :<|> "email" :> Get '[JSON] String


-- | 'Protected' will be protected by 'auths', which we still have to specify.
protected :: AuthResult User -> Server Protected
-- If we get an "Authenticated v", we can trust the information in v, since
-- it was signed by a key we trust.
protected (Authenticated user) = return (name user) :<|> return (email user)
-- Otherwise, we return a 401.
protected _ = throwAll err401

type Unprotected =
 "login"
     :> ReqBody '[JSON] Login
     :> PostNoContent '[JSON] (Headers '[ Header "Set-Cookie" SetCookie
                                        , Header "Set-Cookie" SetCookie]
                                       NoContent)
  :<|> Raw

unprotected :: CookieSettings -> JWTSettings -> Server Unprotected
unprotected cs jwts = checkCreds cs jwts :<|> serveDirectory "example/static"

type API auths = (Auth auths User :> Protected) :<|> Unprotected

server :: CookieSettings -> JWTSettings -> Server (API auths)
server cs jwts = protected :<|> unprotected cs jwts

~~~

The code is common to all authentications. In order to pick one or more specific
authentication methods, all we need to do is provide the expect configuration
parameters.

## API tokens

The following example illustrates how to protect an API with tokens.


~~~ {.haskell}
-- In main, we fork the server, and allow new tokens to be created in the
-- command line for the specified user name and email.
mainWithJWT :: IO ()
mainWithJWT = do
  -- We generate the key for signing tokens. This would generally be persisted,
  -- and kept safely
  myKey <- generateKey
  -- Adding some configurations. All authentications require CookieSettings to
  -- be in the context.
  let jwtCfg = defaultJWTSettings myKey
      cfg = defaultCookieSettings :. jwtCfg :. EmptyContext
      --- Here we actually make concrete
      api = Proxy :: Proxy (API '[JWT])
  _ <- forkIO $ run 7249 $ serveWithContext api cfg (server defaultCookieSettings jwtCfg)

  putStrLn "Started server on localhost:7249"
  putStrLn "Enter name and email separated by a space for a new token"

  forever $ do
     xs <- words <$> getLine
     case xs of
       [name', email'] -> do
         etoken <- makeJWT (User name' email') jwtCfg Nothing
         case etoken of
           Left e -> putStrLn $ "Error generating token:t" ++ show e
           Right v -> putStrLn $ "New token:\t" ++ show v
       _ -> putStrLn "Expecting a name and email separated by spaces"

~~~

And indeed:

~~~ {.bash}

./readme JWT

    Started server on localhost:7249
    Enter name and email separated by a space for a new token
    alice alice@gmail.com
    New token:	"eyJhbGciOiJIUzI1NiJ9.eyJkYXQiOnsiZW1haWwiOiJhbGljZUBnbWFpbC5jb20iLCJuYW1lIjoiYWxpY2UifX0.xzOIrx_A9VOKzVO-R1c1JYKBqK9risF625HOxpBzpzE"

curl localhost:7249/name -v

    * Hostname was NOT found in DNS cache
    *   Trying 127.0.0.1...
    * Connected to localhost (127.0.0.1) port 7249 (#0)
    > GET /name HTTP/1.1
    > User-Agent: curl/7.35.0
    > Host: localhost:7249
    > Accept: */*
    >
    < HTTP/1.1 401 Unauthorized
    < Transfer-Encoding: chunked
    < Date: Wed, 07 Sep 2016 20:17:17 GMT
    * Server Warp/3.2.7 is not blacklisted
    < Server: Warp/3.2.7
    <
    * Connection #0 to host localhost left intact

curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJkYXQiOnsiZW1haWwiOiJhbGljZUBnbWFpbC5jb20iLCJuYW1lIjoiYWxpY2UifX0.xzOIrx_A9VOKzVO-R1c1JYKBqK9risF625HOxpBzpzE" \
  localhost:7249/name -v

    * Hostname was NOT found in DNS cache
    *   Trying 127.0.0.1...
    * Connected to localhost (127.0.0.1) port 7249 (#0)
    > GET /name HTTP/1.1
    > User-Agent: curl/7.35.0
    > Host: localhost:7249
    > Accept: */*
    > Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJkYXQiOnsiZW1haWwiOiJhbGljZUBnbWFpbC5jb20iLCJuYW1lIjoiYWxpY2UifX0.xzOIrx_A9VOKzVO-R1c1JYKBqK9risF625HOxpBzpzE
    >
    < HTTP/1.1 200 OK
    < Transfer-Encoding: chunked
    < Date: Wed, 07 Sep 2016 20:16:11 GMT
    * Server Warp/3.2.7 is not blacklisted
    < Server: Warp/3.2.7
    < Content-Type: application/json
    < Set-Cookie: JWT-Cookie=eyJhbGciOiJIUzI1NiJ9.eyJkYXQiOnsiZW1haWwiOiJhbGljZUBnbWFpbC5jb20iLCJuYW1lIjoiYWxpY2UifX0.xzOIrx_A9VOKzVO-R1c1JYKBqK9risF625HOxpBzpzE; HttpOnly; Secure
    <  Set-Cookie: XSRF-TOKEN=TWcdPnHr2QHcVyTw/TTBLQ==; Secure
    <
    * Connection #0 to host localhost left intact
    "alice"%


~~~

## Cookies

What if, in addition to API tokens, we want to expose our API to browsers? All
we need to do is say so!

~~~ {.haskell}
mainWithCookies :: IO ()
mainWithCookies = do
  -- We *also* need a key to sign the cookies
  myKey <- generateKey
  -- Adding some configurations. 'Cookie' requires, in addition to
  -- CookieSettings, JWTSettings (for signing), so everything is just as before
  let jwtCfg = defaultJWTSettings myKey
      cfg = defaultCookieSettings :. jwtCfg :. EmptyContext
      --- Here is the actual change
      api = Proxy :: Proxy (API '[Cookie])
  run 7249 $ serveWithContext api cfg (server defaultCookieSettings jwtCfg)


-- Here is the login handler
checkCreds :: CookieSettings
           -> JWTSettings
           -> Login
           -> Handler (Headers '[ Header "Set-Cookie" SetCookie
                                , Header "Set-Cookie" SetCookie]
                               NoContent)
checkCreds cookieSettings jwtSettings (Login "Ali Baba" "Open Sesame") = do
   -- Usually you would ask a database for the user info. This is just a
   -- regular servant handler, so you can follow your normal database access
   -- patterns (including using 'enter').
   let usr = User "Ali Baba" "ali@email.com"
   mApplyCookies <- liftIO $ acceptLogin cookieSettings jwtSettings usr
   case mApplyCookies of
     Nothing           -> throwError err401
     Just applyCookies -> return $ applyCookies NoContent
checkCreds _ _ _ = throwError err401
~~~

### CSRF and the frontend

CSRF protection works by requiring that there be a header of the same value as
a distinguished cookie that is set by the server on each request. What the
cookie and header name are can be configured (see `xsrfCookieName` and
`xsrfHeaderName` in `CookieSettings`), but by default they are "XSRF-TOKEN" and
"X-XSRF-TOKEN". This means that, if your client is a browser and your are using
cookies, Javascript on the client must set the header of each request by
reading the cookie. For jQuery, and with the default values, that might be:

~~~ { .javascript }

var token = (function() {
  r = document.cookie.match(new RegExp('XSRF-TOKEN=([^;]+)'))
  if (r) return r[1];
)();


$.ajaxPrefilter(function(opts, origOpts, xhr) {
  xhr.setRequestHeader('X-XSRF-TOKEN', token);
  }

~~~


I *believe* nothing at all needs to be done if you're using Angular's `$http`
directive, but I haven't tested this.

# Note on this README

This README is a literate haskell file. Here is 'main', allowing you to pick
between the examples above.

~~~ { .haskell }

main :: IO ()
main = do
  args <- getArgs
  let usage = "Usage: readme (JWT|Cookie)"
  case args of
    ["JWT"] -> mainWithJWT
    ["Cookie"] -> mainWithCookies
    e -> error $ "Arguments: \"" ++ unwords e ++ "\" not understood\n" ++ usage

~~~
