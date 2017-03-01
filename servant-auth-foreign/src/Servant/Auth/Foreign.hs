{-# OPTIONS_GHC -fno-warn-orphans #-}
module Servant.Auth.Foreign where

import Data.Proxy
import Servant.Auth
import Servant.Foreign

import qualified Data.Text as T

instance forall lang ftype api etc a.
    ( HasForeign lang ftype api
    , HasForeignType lang ftype T.Text
    )
  => HasForeign lang ftype (Auth (JWT ': etc) a :> api) where
  type Foreign ftype (Auth (JWT ': etc) a :> api) = Foreign ftype api

  foreignFor lang Proxy Proxy subR =
    foreignFor lang Proxy (Proxy :: Proxy api) req
    where
      req = subR{ _reqHeaders = HeaderArg arg : _reqHeaders subR }
      arg = Arg
        { _argName = PathSegment "Authorization"
        , _argType = typeFor lang (Proxy :: Proxy ftype) (Proxy :: Proxy T.Text)
        }
