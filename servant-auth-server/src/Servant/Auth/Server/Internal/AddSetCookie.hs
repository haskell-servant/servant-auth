{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PolyKinds                  #-}
{-# LANGUAGE UndecidableInstances       #-}
module Servant.Auth.Server.Internal.AddSetCookie where

import           Blaze.ByteString.Builder   (toByteString)
import qualified Data.ByteString            as BS
import qualified Data.ByteString.Base64     as BS64
import           Data.ByteString.Conversion (ToByteString (..))
import           Data.Monoid
import           Data.String                (IsString)
import qualified Data.Text.Encoding         as T
import           GHC.Generics               (Generic)
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
  AddSetCookiesApi (S n) a = AddSetCookiesApi n (AddSetCookieApi a)
  AddSetCookiesApi (S Z) a = AddSetCookieApi a
  AddSetCookiesApi Z a = a

type family AddSetCookieApi a where
  AddSetCookieApi (a :> b) = a :> AddSetCookieApi b
  AddSetCookieApi (a :<|> b) = AddSetCookieApi a :<|> AddSetCookieApi b
  AddSetCookieApi (Verb method stat ctyps (Headers ls a))
     = Verb method stat ctyps (Headers ((Header "Set-Cookie" SetCookie) ': ls) a)
  AddSetCookieApi (Verb method stat ctyps a)
     = Verb method stat ctyps (Headers '[Header "Set-Cookie" SetCookie] a)

data SetCookieList (n :: Nat) :: * where
  SCNil :: SetCookieList Z
  SCCons :: SetCookie -> SetCookieList n -> SetCookieList (S n)

class AddSetCookies (n :: Nat) orig new where
  addSetCookies :: SetCookieList n -> orig -> new

instance AddSetCookies Z orig orig where
  addSetCookies _ = id

instance {-# OVERLAPS #-} AddSetCookies n oldb newb
  => AddSetCookies n (a -> oldb) (a -> newb) where
  addSetCookies cookies oldfn = \val -> addSetCookies cookies $ oldfn val

instance {-# OVERLAPPABLE #-}
  ( Functor m
  , AddHeader "Set-Cookie" SetCookie old new
  ) => AddSetCookies (S Z) (m old) (m new)  where
  addSetCookies (cookie `SCCons` SCNil) oldVal = addHeader cookie <$> oldVal

instance {-# OVERLAPPABLE #-}
  ( Functor m
  , AddSetCookies (S n) (m old) (m cookied)
  , AddHeader "Set-Cookie" SetCookie cookied new
  ) => AddSetCookies (S (S n)) (m old) (m new)  where
  addSetCookies (cookie `SCCons` rest) oldVal =
    addHeader cookie <$> addSetCookies rest oldVal

instance {-# OVERLAPS #-}
  (AddSetCookies n a a', AddSetCookies n b b')
  => AddSetCookies n (a :<|> b) (a' :<|> b') where
  addSetCookies cookies (a :<|> b) = addSetCookies cookies a :<|> addSetCookies cookies b


instance ToHttpApiData SetCookie where
  toHeader = toByteString . renderSetCookie
  toUrlPiece = T.decodeUtf8 . toHeader

csrfCookie :: IO BS.ByteString
csrfCookie = BS64.encode <$> getEntropy 32
