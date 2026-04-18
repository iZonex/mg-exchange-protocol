# MGEP Java bindings

Pure-JVM wire bindings for JDK 17+. No JNI, no native library —
`ByteBuffer` does all the heavy lifting. Mirrors the C# binding
(`bindings/csharp/`) feature-for-feature.

## Coverage

* **Headers**: `FullHeader` with `FrameHeader` + `MessageHeader` fields
* **Trading**: `NewOrderSingle`, `ExecutionReport`, `BusinessReject`
* **Market data**: `BookSnapshotBegin/Level/End`
* **Session**: `ClockStatus`
* **Encoder**: `encodeNewOrder(...)`
* **Flex parser**: `parseFlexString(msg, coreSize, fieldId)` for
  optional text fields (rate-limit codes, halt scopes, etc.)

## Usage

```java
import com.mgep.Mgep;

// Encode
byte[] bytes = Mgep.encodeNewOrder(
    /*orderId*/ 0L, /*clientOrderId*/ 42L, /*instrumentId*/ 7,
    Mgep.SIDE_BUY, Mgep.ORDER_TYPE_LIMIT,
    /*price*/ 150.25, /*quantity*/ 100.0,
    Mgep.TIF_DAY, /*senderCompId*/ 1, /*sequenceNum*/ 1L,
    /*correlationId*/ 0L);
socket.write(bytes);

// Decode
Mgep.FullHeader hdr = Mgep.FullHeader.decode(buf);
if (hdr != null && hdr.isValid()
    && hdr.schemaId == Mgep.SCHEMA_TRADING
    && hdr.messageType == Mgep.MSG_EXEC_REPORT) {
    Mgep.ExecutionReport er = Mgep.ExecutionReport.decode(buf);
    System.out.printf("Fill at %.4f%n", er.lastPxAsDouble());
}

// Parse typed rejects
if (hdr.messageType == Mgep.MSG_BUSINESS_REJECT) {
    String reason = Mgep.parseFlexString(buf, Mgep.BusinessReject.SIZE, 1);
    if (reason != null && reason.startsWith("rate_limited:")) {
        // Back off and retry.
    }
}
```

## Build

```bash
# Compile + run the test harness (no dependencies):
javac -d out src/main/java/com/mgep/*.java src/test/java/com/mgep/*.java
java -cp out com.mgep.MgepTest
```

For Maven/Gradle, the standard layout is already in place —
`src/main/java/com/mgep/Mgep.java` — just add a `pom.xml` / `build.gradle`
of your choice.

## What's not here

Same exclusions as the C# binding: no connection management, no
client-side state (OrderManager, PositionTracker), no encryption.
The Rust reference implementation is the source of truth for those.

## Wire size verification

Struct sizes asserted in `MgepTest.testSizes()`. If a core block grows
on the Rust side, this test fails and the Java binding must be updated.
Current sizes:

| Message | Bytes |
|---|---|
| NewOrderSingle | 48 |
| ExecutionReport | 88 |
| BusinessReject | 16 |
| BookSnapshotBegin | 40 |
| BookSnapshotLevel | 40 |
| BookSnapshotEnd | 32 |
| ClockStatus | 40 |
