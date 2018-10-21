{-# LANGUAGE OverloadedStrings #-}

import Set5
import qualified Control.Exception as E
import qualified Data.ByteString.Char8 as C
import Network.Socket hiding (recv)
import Network.Socket.ByteString (recv, sendAll)

main :: IO ()
main = withSocketsDo $ do
    addr <- resolve "127.0.0.1" "3000"
    E.bracket (open addr) close talk
  where
    resolve host port = do
        let hints = defaultHints { addrSocketType = Stream }
        addr:_ <- getAddrInfo (Just hints) (Just host) (Just port)
        return addr
    open addr = do
        sock <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
        connect sock $ addrAddress addr
        return sock
    talk sock = do
        sendAll sock "Hello, world!"
        msg <- recv sock 1024
        putStr "Received: "
        C.putStrLn msg



-- ex36 = do
--   -- C & S agree on constants
--   let n = read pDH :: Integer
--       g = 2
--       k = 3
--       email = "jie@mail.com"
--       password = "super secret"
--   -- S: salt, v
--   salt <- randomIO :: IO Integer
--   let xH = sha256 $ B.append (intToByteString salt) password
--       x = read $ "0x" ++ (byteStringToHex xH) :: Integer
--       v = expMod g x n
--   -- C->S: Send I, A=g**a % N (a la Diffie Hellman)
--   (a, _, _) <- generateParam
--   let sa = expMod g a n
--   -- S->C: Send salt, B=kv + g**b % N
--   (b, _, _) <- generateParam
--   let sb = k * v + expMod g b n
--   -- S, C: Compute string uH = SHA256(A|B), u = integer of uH
--       uH = sha256 (B.append (intToByteString sa) (intToByteString sb))
--       u = read $ "0x" ++ (byteStringToHex uH) :: Integer
--   -- C
--       -- xH = ...
--       -- x = ...
--       sForA = expMod (sb - k * expMod g x n) (a + u * x) n
--       ka = sha256 (intToByteString sForA)
--   -- S
--       sForB = expMod (sa * expMod v u n) b n
--       kb = sha256 (intToByteString sForB)
--   -- C->S: Send HMAC-SHA256(K, salt)
--       msgA = hMAC sha256 64 ka (intToByteString salt)
--   -- S->C: Send "OK" if HMAC-SHA256(K, salt) validates
--   if msgA == hMAC sha256 64 kb (intToByteString salt)
--     then print "OK"
--     else print "Not OK"
