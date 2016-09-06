module Servant.Auth.ServerSpec (spec) where

import           Control.Lens
import           Control.Monad
import           Crypto.JOSE              (Alg (HS256, None, HS384), Error, JWK,
                                           KeyMaterialGenParam (OctGenParam),
                                           Protection (Protected), ToCompact,
                                           encodeCompact, genJWK, newJWSHeader)
import           Crypto.JWT               (NumericDate (NumericDate), claimExp,
                                           claimNbf, createJWSJWT,
                                           emptyClaimsSet, unregisteredClaims)
import           Data.Aeson               (FromJSON, ToJSON, toJSON)
import qualified Data.ByteString.Lazy     as BSL
import           Data.Monoid
import           Data.Time
import           GHC.Generics             (Generic)
import           Network.HTTP.Client      (HttpException (StatusCodeException))
import           Network.HTTP.Types       (status200, status400, status401,
                                           status403)
import           Network.Wai              (Application)
import           Network.Wai.Handler.Warp (testWithApplication)
import           Network.Wreq             (Options, defaults, get, getWith,
                                           header, responseBody, responseStatus)
import           Servant
import           Servant.Auth.Server
import           System.IO.Unsafe         (unsafePerformIO)
import           Test.Hspec
import           Test.QuickCheck

spec :: Spec
spec = do
  authSpec
  jwtAuthSpec

------------------------------------------------------------------------------
-- * Auth {{{

authSpec :: Spec
authSpec
  = describe "The Auth combinator"
  $ around (testWithApplication . return $ app jwtAndCookieApi) $ do

  let url port = "http://localhost:" <> show port

      claims val = emptyClaimsSet & unregisteredClaims . at "dat" .~ Just val

      shouldHTTPErrorWith act stat = act `shouldThrow` \e -> case e of
        StatusCodeException x _ _ -> x == stat
        _ -> False

  it "returns a 401 if all authentications are Indefinite" $ \port -> do
    get (url port) `shouldHTTPErrorWith` status401

  it "succeeds if one authentication suceeds" $ const pending
  it "fails (403) if one authentication fails" $ const pending


-- }}}
------------------------------------------------------------------------------
-- * JWT Auth {{{

jwtAuthSpec :: Spec
jwtAuthSpec
  = describe "JWT authentication"
  $ around (testWithApplication . return $ app jwtOnlyApi) $ do

  let url port = "http://localhost:" <> show port

      claims val = emptyClaimsSet & unregisteredClaims . at "dat" .~ Just val

      shouldHTTPErrorWith act stat = act `shouldThrow` \e -> case e of
        StatusCodeException x _ _ -> x == stat
        _ -> False

      addJwtToHeader :: ToCompact a => Either Error a -> IO Options
      addJwtToHeader jwt = case jwt >>= encodeCompact of
        Left e -> fail $ show e
        Right v -> return
          $ defaults & header "Authorization" .~ ["Bearer " <> BSL.toStrict v]

  it "fails if 'nbf' is set to a future date" $ \port -> property $
                                                \(user :: User) -> do
    jwt <- createJWSJWT theKey (newJWSHeader (Protected, HS256))
      (claims (toJSON user) & claimNbf .~ Just (NumericDate future))
    opts <- addJwtToHeader jwt
    getWith opts (url port) `shouldHTTPErrorWith` status401

  it "fails if 'exp' is set to a past date" $ \port -> property $
                                              \(user :: User) -> do
    jwt <- createJWSJWT theKey (newJWSHeader (Protected, HS256))
      (claims (toJSON user) & claimExp .~ Just (NumericDate past))
    opts <- addJwtToHeader jwt
    getWith opts (url port) `shouldHTTPErrorWith` status401

  it "succeeds if 'exp' is set to a future date" $ \port -> property $
                                                   \(user :: User) -> do
    jwt <- createJWSJWT theKey (newJWSHeader (Protected, HS256))
      (claims (toJSON user) & claimExp .~ Just (NumericDate future))
    opts <- addJwtToHeader jwt
    resp <- getWith opts (url port)
    resp ^. responseStatus `shouldBe` status200

  it "fails if JWT is not signed" $ \port -> property $ \(user :: User) -> do
    jwt <- createJWSJWT theKey (newJWSHeader (Protected, None))
                               (claims $ toJSON user)
    opts <- addJwtToHeader jwt
    getWith opts (url port) `shouldHTTPErrorWith` status401

  it "fails if JWT does not use expected algorithm" $ const $
    pendingWith "Need https://github.com/frasertweedale/hs-jose/issues/19"

  it "fails if data is not valid JSON" $ \port -> do
    jwt <- createJWSJWT theKey (newJWSHeader (Protected, HS256)) (claims "{{")
    opts <- addJwtToHeader jwt
    getWith opts (url port) `shouldHTTPErrorWith` status401

-- }}}
------------------------------------------------------------------------------
-- * API and Server {{{

type API auths = Auth auths User :> Get '[JSON] Int

jwtOnlyApi :: Proxy (API '[JWT])
jwtOnlyApi = Proxy

jwtAndCookieApi :: Proxy (API '[JWT, Cookie])
jwtAndCookieApi = Proxy

theKey :: JWK
theKey = unsafePerformIO . genJWK $ OctGenParam 256
{-# NOINLINE theKey #-}

-- | Takes a proxy parameter indicating which authentication systems to enable.
app :: AreAuths auths '[CookieAuthConfig, JWTAuthConfig] User
  => Proxy (API auths) -> Application
app api = serveWithContext api ctx server
  where
    jwtCfg :: JWTAuthConfig
    jwtCfg = defaultJWTAuthConfig theKey

    cookieCfg :: CookieAuthConfig
    cookieCfg = defaultCookieAuthConfig theKey

    ctx = cookieCfg :. jwtCfg :. EmptyContext


server :: Server (API auths)
server = getInt
  where
    getInt :: AuthResult User -> Handler Int
    getInt (Authenticated usr) = return . length $ name usr
    getInt Indefinite = throwError err401
    getInt _ = throwError err403

-- }}}
------------------------------------------------------------------------------
-- * Utils {{{

past :: UTCTime
past = parseTimeOrError True defaultTimeLocale "%Y-%m-%d" "1970-01-01"

future :: UTCTime
future = parseTimeOrError True defaultTimeLocale "%Y-%m-%d" "2070-01-01"

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
