module Servant.Auth.ForeignSpec (spec) where

import Servant
import Lackey
import System.IO.Temp (withSystemTempFile)
import System.Process.Typed
import Data.Monoid

import qualified Data.Text as T

spec :: Spec
spec = do
  lackeySpec

lackeySpec :: Spec
lackeySpec = describe "Foreign instance" $ around testWithApplication $ do

  it "works for dynamic languages" $ \port -> do
    rubyReturns port "simple_get(connection)" "5"


type API
  = Auth '[JWT] User :> "simple" :> Get '[JSON] Int

api :: Proxy API
api = Proxy

theKey :: JWK
theKey = unsafePerformIO . genJWK $ OctGenParam 256
{-# NOINLINE theKey #-}

server :: Server API
server = getInt
  where
    getInt (Authenticated usr) = return $ length (username usr)
    getInt _ = throwError err401

jwtCfg :: JWTSettings
jwtCfg = defaultJWTSettings theKey

app :: Application
app = serveWithContext $ jwtCfg :. theKey :. EmptyContext

rubyClient :: T.Text
rubyClient = rubyForAPI api

rubyReturns :: Int -> T.Text -> T.Text -> Expectation
rubyReturns port command expected = withSystemTempFile "servantAuthTest.rb" $ \file -> do
  let preamble
       = "require 'excon'"
      <> "connection = Excon.new('localhost:" <> T.pack (show port) <> "')\n"
  T.writeFile file $ preamble <> rubyClient <> "\n" <> command
  (err, out, _) <- readProcess (proc "ruby" [file])
  err `shouldBe` exitSuccess
  out `shouldBe` expected
