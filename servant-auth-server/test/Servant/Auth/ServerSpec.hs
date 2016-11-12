module Servant.Auth.ServerSpec (spec) where

import           Control.Lens
import           Control.Monad.Except     (runExceptT)
import           Crypto.JOSE              (Alg (HS256, None), Error, JWK,
                                           JWSHeader,
                                           KeyMaterialGenParam (OctGenParam),
                                           Protection (Protected), ToCompact,
                                           encodeCompact, genJWK, newJWSHeader)
import           Crypto.JWT               (Audience (..), ClaimsSet, JWT,
                                           NumericDate (NumericDate), claimAud,
                                           claimNbf, createJWSJWT,
                                           emptyClaimsSet, unregisteredClaims)
import           Data.Aeson               (FromJSON, ToJSON, Value, toJSON)
import           Data.Aeson.Lens          (_JSON)
import qualified Data.ByteString          as BS
import qualified Data.ByteString.Lazy     as BSL
import           Data.CaseInsensitive     (mk)
import           Data.Foldable            (find)
import           Data.Monoid
import           Data.Time
import           GHC.Generics             (Generic)
import           Network.HTTP.Client      (HttpException (StatusCodeException),
                                           cookie_http_only, cookie_name,
                                           cookie_value, destroyCookieJar)
import           Network.HTTP.Types       (Status, status200, status401)
import           Network.Wai.Handler.Warp (testWithApplication)
import           Network.Wreq             (Options, auth, basicAuth,
                                           cookieExpiryTime, cookies, defaults,
                                           get, getWith, header, oauth2Bearer,
                                           postWith, responseBody,
                                           responseCookieJar, responseStatus)
import           Servant                  hiding (BasicAuth, IsSecure (..))
import           Servant.Auth.Server
import           System.IO.Unsafe         (unsafePerformIO)
import           Test.Hspec
import           Test.QuickCheck

spec :: Spec
spec = do
  authSpec
  cookieAuthSpec
  jwtAuthSpec
  throwAllSpec
  basicAuthSpec

------------------------------------------------------------------------------
-- * Auth {{{

authSpec :: Spec
authSpec
  = describe "The Auth combinator"
  $ around (testWithApplication . return $ app jwtAndCookieApi) $ do

  it "returns a 401 if all authentications are Indefinite" $ \port -> do
    get (url port) `shouldHTTPErrorWith` status401

  it "succeeds if one authentication suceeds" $ \port -> property $
                                                \(user :: User) -> do
    jwt <- makeJWT user jwtCfg Nothing
    opts <- addJwtToHeader jwt
    resp <- getWith opts (url port)
    resp ^? responseBody . _JSON `shouldBe` Just (length $ name user)

  it "fails (403) if one authentication fails" $ const $
    pendingWith "Authentications don't yet fail, only are Indefinite"

  context "Setting cookies" $ do

    it "sets cookies that it itself accepts" $ \port -> property $ \user -> do
      jwt <- createJWT theKey (newJWSHeader (Protected, HS256))
        (claims $ toJSON user)
      opts' <- addJwtToCookie jwt
      let opts = addCookie (opts' & header (mk (xsrfHeaderName cookieCfg)) .~ ["blah"])
                           (xsrfCookieName cookieCfg <> "=blah")
      resp <- getWith opts (url port)
      let (cookieJar:_) = resp ^.. responseCookieJar
          Just xxsrf = find (\x -> cookie_name x == xsrfCookieName cookieCfg)
                     $ destroyCookieJar cookieJar
          opts2 = defaults
            & cookies .~ Just cookieJar
            & header (mk (xsrfHeaderName cookieCfg)) .~ [cookie_value xxsrf]
      resp2 <- getWith opts2 (url port)
      resp2 ^? responseBody . _JSON `shouldBe` Just (length $ name user)

    it "uses the Expiry from the configuration" $ \port -> property $ \(user :: User) -> do
      jwt <- createJWT theKey (newJWSHeader (Protected, HS256))
        (claims $ toJSON user)
      opts' <- addJwtToCookie jwt
      let opts = addCookie (opts' & header (mk (xsrfHeaderName cookieCfg)) .~ ["blah"])
                           (xsrfCookieName cookieCfg <> "=blah")
      resp <- getWith opts (url port)
      let (cookieJar:_) = resp ^.. responseCookieJar
          Just xxsrf = find (\x -> cookie_name x == xsrfCookieName cookieCfg)
                     $ destroyCookieJar cookieJar
      xxsrf ^. cookieExpiryTime `shouldBe` future

    it "sets the token cookie as HttpOnly" $ \port -> property $ \(user :: User) -> do
      jwt <- createJWT theKey (newJWSHeader (Protected, HS256))
        (claims $ toJSON user)
      opts' <- addJwtToCookie jwt
      let opts = addCookie (opts' & header (mk (xsrfHeaderName cookieCfg)) .~ ["blah"])
                           (xsrfCookieName cookieCfg <> "=blah")
      resp <- getWith opts (url port)
      let (cookieJar:_) = resp ^.. responseCookieJar
          Just token = find (\x -> cookie_name x == "JWT-Cookie")
                     $ destroyCookieJar cookieJar
      cookie_http_only token `shouldBe` True



-- }}}
------------------------------------------------------------------------------
-- * Cookie Auth {{{

cookieAuthSpec :: Spec
cookieAuthSpec
  = describe "The Auth combinator"
  $ around (testWithApplication . return $ app cookieOnlyApi) $ do

  it "fails if CSRF header and cookie don't match" $ \port -> property
                                                   $ \(user :: User) -> do
    jwt <- createJWT theKey (newJWSHeader (Protected, HS256)) (claims $ toJSON user)
    opts' <- addJwtToCookie jwt
    let opts = addCookie (opts' & header (mk (xsrfHeaderName cookieCfg)) .~ ["blah"])
                         (xsrfCookieName cookieCfg <> "=blerg")
        emptyBody = "" :: BS.ByteString
    postWith opts (url port) emptyBody `shouldHTTPErrorWith` status401

  it "fails if there is no CSRF header and cookie" $ \port -> property
                                                   $ \(user :: User) -> do
    jwt <- createJWT theKey (newJWSHeader (Protected, HS256)) (claims $ toJSON user)
    opts <- addJwtToCookie jwt
    let emptyBody = "" :: BS.ByteString
    postWith opts (url port) emptyBody `shouldHTTPErrorWith` status401

  it "succeeds if CSRF header and cookie match, and JWT is valid" $ \port -> property
                                                                  $ \(user :: User) -> do
    jwt <- createJWT theKey (newJWSHeader (Protected, HS256)) (claims $ toJSON user)
    opts' <- addJwtToCookie jwt
    let opts = addCookie (opts' & header (mk (xsrfHeaderName cookieCfg)) .~ ["blah"])
                         (xsrfCookieName cookieCfg <> "=blah")
        emptyBody = "" :: BS.ByteString
    resp <- postWith opts (url port) emptyBody
    resp ^? responseStatus `shouldBe` Just status200

  it "succeeds if there is a cookie but no CSRF header for a stateless method" $ \port -> property
                                                                               $ \(user :: User) -> do
    jwt <- createJWT theKey (newJWSHeader (Protected, HS256)) (claims $ toJSON user)
    opts <- addJwtToCookie jwt
    resp <- getWith opts (url port)
    resp ^? responseBody . _JSON `shouldBe` Just (length $ name user)

-- }}}
------------------------------------------------------------------------------
-- * JWT Auth {{{

jwtAuthSpec :: Spec
jwtAuthSpec
  = describe "The JWT combinator"
  $ around (testWithApplication . return $ app jwtOnlyApi) $ do

  it "fails if 'aud' does not match predicate" $ \port -> property $
                                                \(user :: User) -> do
    jwt <- createJWT theKey (newJWSHeader (Protected, HS256))
      (claims (toJSON user) & claimAud .~ Just (Audience ["boo"]))
    opts <- addJwtToHeader (jwt >>= encodeCompact)
    getWith opts (url port) `shouldHTTPErrorWith` status401

  it "succeeds if 'aud' does match predicate" $ \port -> property $
                                                \(user :: User) -> do
    jwt <- createJWT theKey (newJWSHeader (Protected, HS256))
      (claims (toJSON user) & claimAud .~ Just (Audience ["anythingElse"]))
    opts <- addJwtToHeader (jwt >>= encodeCompact)
    resp <- getWith opts (url port)
    resp ^. responseStatus `shouldBe` status200

  it "fails if 'nbf' is set to a future date" $ \port -> property $
                                                \(user :: User) -> do
    jwt <- createJWT theKey (newJWSHeader (Protected, HS256))
      (claims (toJSON user) & claimNbf .~ Just (NumericDate future))
    opts <- addJwtToHeader (jwt >>= encodeCompact)
    getWith opts (url port) `shouldHTTPErrorWith` status401

  it "fails if 'exp' is set to a past date" $ \port -> property $
                                              \(user :: User) -> do
    jwt <- makeJWT user jwtCfg (Just past)
    opts <- addJwtToHeader jwt
    getWith opts (url port) `shouldHTTPErrorWith` status401

  it "succeeds if 'exp' is set to a future date" $ \port -> property $
                                                   \(user :: User) -> do
    jwt <- makeJWT user jwtCfg (Just future)
    opts <- addJwtToHeader jwt
    resp <- getWith opts (url port)
    resp ^. responseStatus `shouldBe` status200

  it "fails if JWT is not signed" $ \port -> property $ \(user :: User) -> do
    jwt <- createJWT theKey (newJWSHeader (Protected, None))
                               (claims $ toJSON user)
    opts <- addJwtToHeader (jwt >>= encodeCompact)
    getWith opts (url port) `shouldHTTPErrorWith` status401

  it "fails if JWT does not use expected algorithm" $ const $
    pendingWith "Need https://github.com/frasertweedale/hs-jose/issues/19"

  it "fails if data is not valid JSON" $ \port -> do
    jwt <- createJWT theKey (newJWSHeader (Protected, HS256)) (claims "{{")
    opts <- addJwtToHeader (jwt >>= encodeCompact)
    getWith opts (url port) `shouldHTTPErrorWith` status401

  it "suceeds as wreq's oauth2Bearer" $ \port -> property $ \(user :: User) -> do
    jwt <- createJWT theKey (newJWSHeader (Protected, HS256))
                               (claims $ toJSON user)
    resp <- case jwt >>= encodeCompact of
      Left (e :: Error) -> fail $ show e
      Right v -> getWith (defaults & auth ?~ oauth2Bearer (BSL.toStrict v)) (url port)
    resp ^. responseStatus `shouldBe` status200

-- }}}
------------------------------------------------------------------------------
-- * Basic Auth {{{

basicAuthSpec :: Spec
basicAuthSpec = describe "The BasicAuth combinator"
  $ around (testWithApplication . return $ app basicAuthApi) $ do

  it "succeeds with the correct password and username" $ \port -> do
    resp <- getWith (defaults & auth ?~ basicAuth "ali" "Open sesame") (url port)
    resp ^. responseStatus `shouldBe` status200

  it "fails with non-existent user" $ \port -> do
    getWith (defaults & auth ?~ basicAuth "thief" "Open sesame") (url port)
      `shouldHTTPErrorWith` status401

  it "fails with incorrect password" $ \port -> do
    getWith (defaults & auth ?~ basicAuth "ali" "phatic") (url port)
      `shouldHTTPErrorWith` status401

  it "fails with no auth header" $ \port -> do
    get (url port) `shouldHTTPErrorWith` status401

-- }}}
------------------------------------------------------------------------------
-- * ThrowAll {{{

throwAllSpec :: Spec
throwAllSpec = describe "throwAll" $ do

  it "works for plain values" $ do
    let t :: Either ServantErr Int :<|> Either ServantErr Bool :<|> Either ServantErr String
        t = throwAll err401
    t `shouldBe` throwError err401 :<|> throwError err401 :<|> throwError err401

  it "works for function types" $ property $ \i -> do
    let t :: Int -> (Either ServantErr Bool :<|> Either ServantErr String)
        t = throwAll err401
        expected _ = throwError err401 :<|> throwError err401
    t i `shouldBe` expected i

-- }}}
------------------------------------------------------------------------------
-- * API and Server {{{

type Protected = Get '[JSON] Int :<|> Post '[JSON] ()

type API auths = Auth auths User :> Protected

jwtOnlyApi :: Proxy (API '[Servant.Auth.Server.JWT])
jwtOnlyApi = Proxy

cookieOnlyApi :: Proxy (API '[Cookie])
cookieOnlyApi = Proxy

basicAuthApi :: Proxy (API '[BasicAuth])
basicAuthApi = Proxy

jwtAndCookieApi :: Proxy (API '[Servant.Auth.Server.JWT, Cookie])
jwtAndCookieApi = Proxy

theKey :: JWK
theKey = unsafePerformIO . genJWK $ OctGenParam 256
{-# NOINLINE theKey #-}


cookieCfg :: CookieSettings
cookieCfg = def
  { xsrfCookieName = "TheyDinedOnMince"
  , xsrfHeaderName = "AndSlicesOfQuince"
  , cookieExpires = Just future
  , cookieIsSecure = NotSecure
  }

jwtCfg :: JWTSettings
jwtCfg = (defaultJWTSettings theKey) { audienceMatches = \x ->
    if x == "boo" then DoesNotMatch else Matches }

instance FromBasicAuthData User where
  fromBasicAuthData (BasicAuthData usr pwd) _
    = return $ if usr == "ali" && pwd == "Open sesame"
      then Authenticated $ User "ali" "ali@the-thieves-den.com"
      else Indefinite

-- Could be anything, really, but since this is already in the cfg we don't
-- have to add it
type instance BasicAuthCfg = JWK

-- | Takes a proxy parameter indicating which authentication systems to enable.
app :: AreAuths auths '[CookieSettings, JWTSettings, JWK] User
  => Proxy (API auths) -> Application
app api = serveWithContext api ctx server
  where
    ctx = cookieCfg :. jwtCfg :. theKey :. EmptyContext

server :: Server (API auths)
server = protected
  where
    protected :: AuthResult User -> Server Protected
    protected (Authenticated usr) = return (length $ name usr)
                               :<|> return ()
    protected Indefinite = throwAll err401
    protected _ = throwAll err403

-- }}}
------------------------------------------------------------------------------
-- * Utils {{{

past :: UTCTime
past = parseTimeOrError True defaultTimeLocale "%Y-%m-%d" "1970-01-01"

future :: UTCTime
future = parseTimeOrError True defaultTimeLocale "%Y-%m-%d" "2070-01-01"

addJwtToHeader :: Either Error BSL.ByteString -> IO Options
addJwtToHeader jwt = case jwt of
  Left e -> fail $ show e
  Right v -> return
    $ defaults & header "Authorization" .~ ["Bearer " <> BSL.toStrict v]

createJWT :: JWK -> JWSHeader -> ClaimsSet -> IO (Either Error Crypto.JWT.JWT)
createJWT k a b = runExceptT $ createJWSJWT k a b

addJwtToCookie :: ToCompact a => Either Error a -> IO Options
addJwtToCookie jwt = case jwt >>= encodeCompact of
  Left e -> fail $ show e
  Right v -> return
    $ defaults & header "Cookie" .~ ["JWT-Cookie=" <> BSL.toStrict v]

addCookie :: Options -> BS.ByteString -> Options
addCookie opts cookie' = opts & header "Cookie" %~ \c -> case c of
                        [h] -> [cookie' <> "; " <> h]
                        []  -> [cookie']
                        _   -> error "expecting single cookie header"

shouldHTTPErrorWith :: IO a -> Status -> Expectation
shouldHTTPErrorWith act stat = act `shouldThrow` \e -> case e of
  StatusCodeException x _ _ -> x == stat
  _ -> False

url :: Int -> String
url port = "http://localhost:" <> show port

claims :: Value -> ClaimsSet
claims val = emptyClaimsSet & unregisteredClaims . at "dat" .~ Just val
-- }}}
------------------------------------------------------------------------------
-- * Types {{{

data User = User
  { name :: String
  , _id  :: String
  } deriving (Eq, Show, Read, Generic)

instance FromJWT User
instance ToJWT User
instance FromJSON User
instance ToJSON User

instance Arbitrary User where
  arbitrary = User <$> arbitrary <*> arbitrary

-- }}}
