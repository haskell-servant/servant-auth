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
  jwtAuthSpec


jwtAuthSpec :: Spec
jwtAuthSpec
  = describe "JWT authentication" $ around (testWithApplication $ return app) $ do

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

{-
  it "accepts JWTs created with makeJWT and the same config" $ \port -> property
                                                             $ \user -> do
    jwt <- runExceptT $ makeJWT cfg user Nothing AlwaysValid
    opts <- case jwt of
        Left e -> fail $ show e
        Right v -> return
          $ defaults & header "Authorization" .~ ["Bearer " <> unToken v]
    resp <- getWith opts (url port)
    resp ^. responseStatus `shouldBe` status200
    resp ^? responseBody `shouldBe` Just (encode . length $ name user)

  it "allows checking the JTI" $ \port -> property $ \user -> do
    jwt <- runExceptT $ makeJWT cfg user (Just "revoked!") AlwaysValid
    opts <- case jwt of
        Left e -> fail $ show e
        Right v -> return
          $ defaults & header "Authorization" .~ ["Bearer " <> unToken v]
    getWith opts (url port) `shouldHTTPErrorWith` status403

    -}

------------------------------------------------------------------------------
-- * API and Server {{{

type API auths = Auth auths User :> Get '[JSON] Int

jwtOnlyApi :: Proxy (API '[JWT])
jwtOnlyApi = Proxy

theKey :: JWK
theKey = unsafePerformIO . genJWK $ OctGenParam 256
{-# NOINLINE theKey #-}

app :: Application
app = serveWithContext jwtOnlyApi ctx server
  where
    ctx = cfg :. EmptyContext

cfg :: JWTAuthConfig
cfg = defaultJWTAuthConfig theKey

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
