{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PolyKinds                  #-}
{-# LANGUAGE UndecidableInstances       #-}
module Servant.Auth.Server.Internal.AddSetCookie where

import qualified Data.ByteString            as BS
import qualified Data.ByteString.Base64     as BS64
import           Servant

import           System.Entropy             (getEntropy)
import           Web.Cookie

-- What are we doing here? Well, the idea is to add headers to the response,
-- but the headers come from the authentication check. In order to do that, we
-- tweak a little the general theme of recursing down the API tree; this time,
-- we recurse down a variation of it that adds headers to all the endpoints.
-- This involves the usual type-level checks.
--
-- TODO: If the endpoints already have headers, this will not work as is.

data Nat = Z | S Nat

type family AddSetCookiesApi (n :: Nat) a where
  AddSetCookiesApi ('S 'Z) a = AddSetCookieApi a
  AddSetCookiesApi ('S n) a = AddSetCookiesApi n (AddSetCookieApi a)

type family AddSetCookieApi a where
  AddSetCookieApi (a :> b) = a :> AddSetCookieApi b
  AddSetCookieApi (a :<|> b) = AddSetCookieApi a :<|> AddSetCookieApi b
  AddSetCookieApi (Verb method stat ctyps (Headers ls a))
     = Verb method stat ctyps (Headers ((Header "Set-Cookie" SetCookie) ': ls) a)
  AddSetCookieApi (Verb method stat ctyps a)
     = Verb method stat ctyps (Headers '[Header "Set-Cookie" SetCookie] a)

data SetCookieList (n :: Nat) :: * where
  SetCookieNil :: SetCookieList 'Z
  SetCookieCons :: Maybe SetCookie -> SetCookieList n -> SetCookieList ('S n)

class AddSetCookies (n :: Nat) orig new where
  addSetCookies :: SetCookieList n -> orig -> new

instance {-# OVERLAPS #-} AddSetCookies n oldb newb
  => AddSetCookies n (a -> oldb) (a -> newb) where
  addSetCookies cookies oldfn = \val -> addSetCookies cookies $ oldfn val

instance AddSetCookies 'Z orig orig where
  addSetCookies _ = id

instance {-# OVERLAPPABLE #-}
  ( Functor m
  , AddSetCookies n (m old) (m cookied)
  , AddHeader "Set-Cookie" SetCookie cookied new
  ) => AddSetCookies ('S n) (m old) (m new)  where
  addSetCookies (mCookie `SetCookieCons` rest) oldVal =
    case mCookie of
      Nothing -> noHeader <$> addSetCookies rest oldVal
      Just cookie -> addHeader cookie <$> addSetCookies rest oldVal

instance {-# OVERLAPS #-}
  (AddSetCookies n a a', AddSetCookies n b b')
  => AddSetCookies n (a :<|> b) (a' :<|> b') where
  addSetCookies cookies (a :<|> b) = addSetCookies cookies a :<|> addSetCookies cookies b

csrfCookie :: IO BS.ByteString
csrfCookie = BS64.encode <$> getEntropy 32
