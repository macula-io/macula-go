macula-go frame samples: one frame per file, exactly as written to a QUIC stream
(4-byte big-endian length, then the deterministic CBOR body).

SDK: macula-go, branch verified-caller at 8a8f718. Frame encoding is unchanged
since the v0.9.0 tag (251177d): nothing under frame/ or cbor's encoder differs
apart from Sign copying a frame's entries before it sets the signature.
macula-ts, macula-php, macula-mcp and macula-cli send through this encoder.

Captured from the send paths, with throwaway identities:
  call.bin, call.ucan.bin     Session.Call, Session.CallWithUCAN
  publish.bin                 Session.Publish (publisher_sig, then signature)
  subscribe.bin               Session.Subscribe
  unsubscribe.bin             Subscription.Close of the topic's only subscription
  advertise.bin               Session.Advertise
  unadvertise.bin             Session.Unadvertise
  result.bin                  ServeOneCall answering a CALL it serves
  error.bin                   ServeOneCall, no handler (unknown_next_peer, no detail)
  error.detail.bin            ServeOneCall, handler error (detail set)
  goodbye.bin                 Session.Close("normal", nil)
  stream_data.bin             Handle.SendData, raw encoding
  stream_data.msgpack.bin     Handle.SendData, msgpack encoding
  stream_end.bin              Handle.CloseSend
  stream_reply.bin            Handle.SendReply
  stream_error.bin            Handle.Abort
Built as the send path builds it (needs a live dial to capture):
  connect.bin                 connectOne's CONNECT
  stream_open.bin             stream.Open's STREAM_OPEN
Go never sends EVENT or HELLO. DHT and content operations go out as CALL frames.
