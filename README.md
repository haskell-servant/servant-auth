# servant-auth

This package provides safe and easy-to-use authentication options for
`servant`. The same API can be protected via login and cookies, or API tokens,
without much extra work.


## API tokens


~~~ {.haskell}
import Control.Concurrent (forkIO)
import Control.Monad (forever)
import Control.Monad.Trans.Except (runExceptT)
import Data.Aeson (FromJSON, ToJSON)
import GHC.Generics (Generic)
import Network.Wai.Handler.Warp (run)
import Servant
import Servant.Auth.Server

data User = User { name :: String, email :: String }
   deriving (Eq, Show, Read, Generic)

instance ToJSON User
instance ToJWT User
instance FromJSON User
instance FromJWT User


type Protected = "name" :> Get '[JSON] String
            :<|> "email" :> Get '[JSON] String

type Unprotected = Get '[JSON] ()

type API = Auth '[JWT] User :> Protected
      :<|> Unprotected

api :: Proxy API
api = Proxy

server :: Server API
server = protected :<|> unprotected
  where
   protected (Authenticated user) = return (name user) :<|> return (email user)
   protected _ = throwError err401 :<|> throwError err401
   unprotected = return ()

-- In main, we fork the server, and allow new tokens to be created in the
-- command line for the specified user name and email.
main :: IO ()
main = do
  myKey <- generateKey
  let jwtCfg = defaultJWTSettings myKey
      cfg = defaultCookieSettings :. jwtCfg :. EmptyContext
  _ <- forkIO $ run 7249 $ serveWithContext api cfg server
  forever $ do
     xs <- words <$> getLine
     case xs of
       [name', email'] -> do
         etoken <- runExceptT $ makeJWT (User name' email') jwtCfg Nothing
         case etoken of
           Left e -> putStrLn $ "Error generating token:t" ++ show e
           Right v -> putStrLn $ "New token:\t" ++ show v
       _ -> putStrLn "Expecting a name and email separated by spaces"

~~~

## Cookies


### CSRF and the frontend

CSRF protection works by requiring that there be a header of the same value as
a distinguished cookie that is set by the server on each request. What the
cookie and header name are can be configured (see `xsrfCookieName` and
`xsrfHeaderName` in `CookieSettings`), but by default they are "XSRF-TOKEN" and
"X-XSRF-TOKEN". Assuming you use the default values, this means that, if your
client is a browser and your are using cookies, Javascript on the client must
set the header of each request by reading the cookie. For jQuery, that might
be:

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
