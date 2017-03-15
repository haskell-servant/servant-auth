module Main (main) where

-- Runs doctest on all files in "src" dir. Assumes:
--   (a) You are using hpack
--   (b) The top-level "default-extensions" are the only extensions besides the
--   ones in the files.

import System.FilePath.Glob (glob)
import Test.DocTest (doctest)
import Data.Yaml

newtype Exts = Exts { getExts :: [String] }
  deriving (Eq, Show, Read)

instance FromJSON Exts where
  parseJSON (Object v) = Exts <$> v .: "default-extensions"
  parseJSON _ = fail "expecting object"

main :: IO ()
main = do
  hpack' <- decodeFile "package.yaml"
  hpack <- case hpack' of
    Nothing -> return $ Exts []
    Just v  -> return v
  files <- glob "src/**/*.hs"
  doctest $ files ++ fmap ("-X" ++) (getExts hpack)
