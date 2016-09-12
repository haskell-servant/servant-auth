{-# LANGUAGE RecordWildCards #-}
module Servant.Auth.Server.Internal.OpenID where

import Servant
import Servant.Client
import qualified Data.ByteString as BS
import Control.Monad.Except
import Control.Monad.Reader
import GHC.Generics (Generic)
import Crypto.MAC.HMAC (hmac)
import qualified Data.Text as T
import Servant.Auth.Server.Internal.Types
import Network.Wai
import Web.Cookie (parseCookies)

-- http://openid.net/specs/openid-connect-core-1_0.html
-- http://connect2id.com/learn/openid-connect

-- | Generates a redirect URL for step 1 of the process.
redirectClient :: URI -> OpenIDCfg auth tok -> ServantErr
redirectClient redirectURI OpenIDCfg{..} = err302 { errHeaders = [("Location", loc)] }
  where
    pr  = Proxy :: Proxy (AuthorizationEndpoint auth)
    loc = safeLink pr pr
          (Just clientId) (Just Code) (Just redirectURI) (Just state) (Just prompt)

-- | Queries the OP for a token, by providing the code.
getToken :: Code -> Proxy (OpenIDConnectAPI a b) -> ExceptT ServantError IO Token
getToken code (x :<|> _) = client code BaseUrl

-- | This function handles step 2 of the OpenID Connect procedure. That is to
-- say, when the client has returned to the site after authenticating with the
-- Identity Provider (IdP), the request is expected to contain a state and code
-- in the query params. Those are used to get a JWT from the IdP in a separate
-- request. If that suceeds, this check succeeds.
openIDAuthCheck :: AuthCheck usr
openIDAuthCheck = AuthCheck $ do
  qs <- queryString <$> ask
  hdrs <- requestHeaders <$> ask
  do
    stateInHeader <- join $ lookup "state" qs
    cookies' <- lookup "Cookie" hdrs
    let cookies = parseCookies cookies'
    stateInCookie <- lookup "OID-State" cookies

    code <- join $ lookup "code" qs
    lookup "OID-State"




-- servant-style discovery doc schema

type OpenIDConnectAPI aep tep = AuthorizationEndpoint aep :<|> TokenEndpoint tep


type AuthorizationEndpoint path
  =  path
  :> QueryParam "client_id" ClientID
  :> QueryParam "response_type" ResponseType
  :> QueryParam "redirect_uri" URI
  :> QueryParam "state" State
  :> QueryParam "prompt" Prompt
  :> Get '[JSON] ()


type TokenEndpoint path = Post '[FormUrlEncoded] Token


newtype Token = Token { unToken :: BS.ByteString }
  deriving (Eq, Show, Read, Generic)

data Scope = Scope [T.Text]
  deriving (Eq, Show, Read, Generic)

data ResponseType = Code
  deriving (Eq, Show, Read, Generic)

data Prompt = PromptNone | PromptConsent | PromptSelectAccount
  deriving (Eq, Show, Read, Generic)

newtype State = State { unState :: BS.ByteString }
  deriving (Eq, Show, Read, Generic)

-- | This is the secret key used for HMAC
newtype Key = Key { unKey :: BS.ByteString }
  deriving (Eq, Show, Read, Generic)

data ClientID

data OpenIDCfg a b = OpenIDCfg
  { clientId          :: ClientID
  , baseURL           :: BaseUrl
  , scope             :: Scope
  , clientState       :: State
  , prompt            :: Prompt
  , authorizationPath :: Proxy a
  , tokenPath         :: Proxy b
  } deriving (Eq, Show, Read, Generic)
