# MGEP C# bindings

Pure-managed wire bindings for .NET 8+ (Mono/Unity should work too). No
native library, no P/Invoke — MGEP's `#[repr(C)]` core blocks map
directly onto `[StructLayout(LayoutKind.Sequential)]` structs.

## Coverage

* **Headers**: `FrameHeader`, `MessageHeader`, `FullHeader`
* **Trading**: `NewOrderSingle`, `ExecutionReport`, `BusinessReject`
* **Market data**: `BookSnapshotRequest/Begin/Level/End`
* **Session**: `ClockStatus`

## Usage

```csharp
using MGEP;

// Send an order
var bytes = Encoder.EncodeNewOrder(
    orderId: 0, clientOrderId: 42, instrumentId: 7,
    side: Side.Buy, orderType: OrderType.Limit,
    price: 150.25, quantity: 100.0,
    sequenceNum: 1);
socket.Send(bytes);

// Decode an incoming message
var hdr = Decoder.DecodeHeader(buf);
if (hdr?.Message.SchemaId == SchemaId.Trading
    && hdr?.Message.MessageType == 0x05) {
    var er = Decoder.DecodeExecReport(buf);
    Console.WriteLine($"Fill at {er.LastPxAsDouble()}");
}

// Parse typed reject errors
if (hdr?.Message.MessageType == 0x11) {
    var reject = Decoder.DecodeBusinessReject(buf);
    var text = Decoder.ParseFlexString(buf, BusinessReject.Size);
    if (text?.StartsWith("rate_limited:") == true) {
        // Back off, retry later.
    }
}
```

## What's not here

* Connection management, handshake orchestration, reconnect logic —
  use the Rust reference or build on top of these primitives.
* Client-side state (OrderManager, PositionTracker) — port equivalents
  of `client_state.rs` when you need them.
* AES-GCM encryption — not yet exposed via C#.

## Build

```bash
dotnet new classlib
cp Mgep.cs ./
dotnet build
```

## Wire size verification

The struct sizes must match the Rust reference. On any commit that
changes a core block, run `dotnet test` (see `MgepTests.cs` when
added) — the sizes are asserted there.

Current sizes:

| Message | Bytes |
|---|---|
| `NewOrderSingle` | 48 |
| `ExecutionReport` | 88 |
| `BusinessReject` | 16 |
| `BookSnapshotRequest` | 16 |
| `BookSnapshotBegin` | 40 |
| `BookSnapshotLevel` | 40 |
| `BookSnapshotEnd` | 32 |
| `ClockStatus` | 40 |
