#include "../../KEVLAR/host/frameworks/fltmgr_provider.h"
#include "../../KEVLAR/host/frameworks/framework_provider.h"
#include "../../KEVLAR/host/frameworks/kmdf_provider.h"
#include "../../KEVLAR/host/frameworks/ndis_provider.h"
#include "../../KEVLAR/host/frameworks/storport_provider.h"

#include <cassert>
#include <cstdio>
#include <map>
#include <memory>

using namespace Kevlar::Host::Frameworks;

namespace {

const GuestAddressValidator Validator = [](
    GuestAddress Address, std::size_t Size, GuestAccess) {
    return Address >= 0x1000 && Size != 0 && Address + Size >= Address &&
        Address + Size <= 0x100000;
};

NdisDriverCallbacks MakeNdisCallbacks() {
    NdisDriverCallbacks Result;
    Result.Initialize.Address = 0x3000;
    Result.Halt.Address = 0x3010;
    Result.Pause.Address = 0x3020;
    Result.Restart.Address = 0x3030;
    Result.OidRequest.Address = 0x3040;
    Result.CancelOidRequest.Address = 0x3050;
    Result.SendNetBufferLists.Address = 0x3060;
    Result.CancelSend.Address = 0x3070;
    Result.ReceiveNetBufferLists.Address = 0x3080;
    Result.ReturnNetBufferLists.Address = 0x3090;
    return Result;
}

StorportMiniportCallbacks MakeStorportCallbacks() {
    StorportMiniportCallbacks Result;
    Result.FindAdapter.Address = 0x5000;
    Result.Initialize.Address = 0x5010;
    Result.StartIo.Address = 0x5020;
    Result.Interrupt.Address = 0x5030;
    Result.Dpc.Address = 0x5040;
    Result.ResetBus.Address = 0x5050;
    Result.AdapterControl.Address = 0x5060;
    Result.CancelSrb.Address = 0x5070;
    return Result;
}

void KmdfFixture(const std::shared_ptr<KmdfProvider>& Provider) {
    const auto Driver = Provider->CreateObject(KmdfObjectType::Driver);
    assert(Driver && Driver.Value == MakeHandle(0x4B4D, 1));
    const auto Device = Provider->CreateObject(KmdfObjectType::Device, Driver.Value);
    assert(Device);

    KmdfQueueCallbacks QueueCallbacks;
    QueueCallbacks.Read.Address = 0x1200;
    const auto Queue = Provider->CreateQueue(
        Device.Value, KmdfQueueMode::Sequential, QueueCallbacks);
    assert(Queue);
    const auto Request = Provider->CreateRequest(
        Queue.Value, KmdfRequestKind::Read, 0x1300, 64);
    assert(Request);
    assert(Provider->EnqueueRequest(Request.Value) == Status::Success);
    assert(Provider->EnqueueRequest(Request.Value) == Status::InvalidState);
    const auto Dispatch = Provider->DispatchNext(Queue.Value);
    assert(Dispatch && Dispatch.Value.Sequence == 1 &&
        Dispatch.Value.Arguments[1] == Request.Value.Value);
    assert(Provider->CompleteRequest(Request.Value, 0) == Status::Success);
    assert(Provider->CompleteRequest(Request.Value, 0) == Status::InvalidState);

    const auto Saved = Provider->Snapshot();
    KmdfProvider Restored(Validator);
    assert(Restored.Restore(Saved) == Status::Success);
    assert(Restored.Snapshot() == Saved);
    auto Corrupt = Saved;
    Corrupt.NextHandleId = 1;
    assert(Restored.Restore(Corrupt) == Status::CorruptSnapshot);
}

void FltmgrFixture(const std::shared_ptr<FltmgrProvider>& Provider) {
    FltFilterCallbacks FilterCallbacks;
    FilterCallbacks.Unload.Address = 0x1500;
    FilterCallbacks.InstanceSetup.Address = 0x1510;
    FilterCallbacks.InstanceTeardownStart.Address = 0x1520;
    FilterCallbacks.InstanceTeardownComplete.Address = 0x1530;
    FltOperationCallbacks OperationCallbacks;
    OperationCallbacks.Pre.Address = 0x1540;
    OperationCallbacks.Post.Address = 0x1550;

    const auto Filter = Provider->RegisterFilter(
        0x2000, FilterCallbacks, {{0x0E, OperationCallbacks}});
    assert(Filter && Filter.Value == MakeHandle(0x464C, 1));
    assert(Provider->StartFiltering(Filter.Value) == Status::Success);
    assert(Provider->StartFiltering(Filter.Value) == Status::InvalidState);
    const auto Instance = Provider->CreateInstance(Filter.Value, 0x2100);
    assert(Instance);
    const auto Activate = Provider->ActivateInstance(Instance.Value);
    assert(Activate && Activate.Value && Activate.Value->Sequence == 1);
    const auto Begin = Provider->BeginOperation(
        Instance.Value, 0x0E, 0x2200, 0x2300);
    assert(Begin && Begin.Value.PreCallback && Begin.Value.PreCallback->Sequence == 2);
    assert(Provider->AcknowledgePreOperation(Begin.Value.Operation, true, 0x2400) == Status::Success);
    const auto Complete = Provider->CompleteOperation(Begin.Value.Operation, 0);
    assert(Complete && Complete.Value && Complete.Value->Sequence == 3);

    const auto Saved = Provider->Snapshot();
    FltmgrProvider Restored(Validator);
    assert(Restored.Restore(Saved) == Status::Success && Restored.Snapshot() == Saved);
    const auto Detach = Provider->DetachInstance(Instance.Value);
    assert(Detach && Detach.Value.size() == 2 &&
        Detach.Value[0].Sequence == 4 && Detach.Value[1].Sequence == 5);
    const auto Unregister = Provider->UnregisterFilter(Filter.Value);
    assert(Unregister && Unregister.Value && Unregister.Value->Sequence == 6);
}

void NdisFixture(const std::shared_ptr<NdisProvider>& Provider) {
    const auto Miniport = Provider->RegisterMiniport(0x4000, MakeNdisCallbacks());
    const auto Filter = Provider->RegisterFilter(0x4100, MakeNdisCallbacks());
    assert(Miniport && Miniport.Value == MakeHandle(0x4E44, 1));
    assert(Filter && Filter.Value == MakeHandle(0x4E44, 2));
    assert(Provider->RegisterMiniport(0x4000, MakeNdisCallbacks()).Code == Status::Duplicate);

    const auto Initialize = Provider->BeginAdapterInitialization(
        Miniport.Value, 0x4200, 0x4300);
    assert(Initialize && Initialize.Value.Adapter == MakeHandle(0x4E44, 3));
    assert(Initialize.Value.Callback.Sequence == 1);
    const GuestHandle Adapter = Initialize.Value.Adapter;
    assert(Provider->CompleteAdapterInitialization(Adapter, true) == Status::Success);
    assert(Provider->CompleteAdapterInitialization(Adapter, true) == Status::InvalidState);
    const auto Restart = Provider->BeginRestartAdapter(Adapter, 0x4310);
    assert(Restart && Restart.Value.Sequence == 2);
    assert(Provider->CompleteRestartAdapter(Adapter, true) == Status::Success);

    const auto Oid = Provider->BeginOidRequest(Adapter, 7, 0x4400);
    assert(Oid && Oid.Value.Callback.Sequence == 3);
    assert(Provider->BeginOidRequest(Adapter, 7, 0x4410).Code == Status::Duplicate);
    const auto Send = Provider->BeginSend(Adapter, 9, 0x4500, 1, 2);
    assert(Send && Send.Value.Callback.Sequence == 4);
    const auto Receive = Provider->IndicateReceive(Adapter, 0x4600, 1, 2, 3);
    const auto Returned = Provider->ReturnReceive(Adapter, 0x4600, 4);
    assert(Receive && Returned && Receive.Value.Sequence == 5 && Returned.Value.Sequence == 6);
    assert(Provider->BeginPauseAdapter(Adapter, 0x4700).Code == Status::Busy);

    const auto Saved = Provider->Snapshot();
    NdisProvider Restored(Validator);
    assert(Restored.Restore(Saved) == Status::Success && Restored.Snapshot() == Saved);
    auto Corrupt = Saved;
    Corrupt.Adapters.begin()->second.Registration = {};
    assert(Restored.Restore(Corrupt) == Status::CorruptSnapshot);

    const auto CancelOid = Provider->CancelOidRequest(Oid.Value.Operation);
    assert(CancelOid && CancelOid.Value.Sequence == 7);
    assert(Provider->CancelOidRequest(Oid.Value.Operation).Code == Status::InvalidState);
    assert(Provider->CompleteSend(Send.Value.Operation, 0) == Status::Success);
    const auto Pause = Provider->BeginPauseAdapter(Adapter, 0x4700);
    assert(Pause && Pause.Value.Sequence == 8);
    assert(Provider->CompletePauseAdapter(Adapter) == Status::Success);
    const auto Halt = Provider->HaltAdapter(Adapter, 0);
    assert(Halt && Halt.Value.Sequence == 9);
    assert(Provider->HaltAdapter(Adapter, 0).Code == Status::InvalidHandle);
    assert(Provider->Unregister(Miniport.Value) == Status::Success);

    const auto FilterInitialize = Provider->BeginAdapterInitialization(
        Filter.Value, 0x4800, 0x4810);
    assert(FilterInitialize && FilterInitialize.Value.Callback.Sequence == 10);
    const GuestHandle FilterAdapter = FilterInitialize.Value.Adapter;
    assert(Provider->CompleteAdapterInitialization(FilterAdapter, true) == Status::Success);
    assert(Provider->BeginRestartAdapter(FilterAdapter, 0x4820).Value.Sequence == 11);
    assert(Provider->CompleteRestartAdapter(FilterAdapter, true) == Status::Success);
    assert(Provider->BeginPauseAdapter(FilterAdapter, 0x4830).Value.Sequence == 12);
    assert(Provider->CompletePauseAdapter(FilterAdapter) == Status::Success);
    assert(Provider->HaltAdapter(FilterAdapter, 0).Value.Sequence == 13);
    assert(Provider->Unregister(Filter.Value) == Status::Success);
}

void StorportFixture(const std::shared_ptr<StorportProvider>& Provider) {
    const auto Registration = Provider->RegisterMiniport(0x6000, MakeStorportCallbacks());
    assert(Registration && Registration.Value == MakeHandle(0x5350, 1));
    assert(Provider->RegisterMiniport(0x6000, MakeStorportCallbacks()).Code == Status::Duplicate);
    const auto Discovery = Provider->BeginAdapterDiscovery(
        Registration.Value, 0x6100, 0x6200);
    assert(Discovery && Discovery.Value.Adapter == MakeHandle(0x5350, 2));
    assert(Discovery.Value.Callback.Sequence == 1);
    const GuestHandle Adapter = Discovery.Value.Adapter;
    assert(Provider->CompleteAdapterDiscovery(Adapter, true) == Status::Success);
    assert(Provider->CompleteAdapterDiscovery(Adapter, true) == Status::InvalidState);
    const auto Start = Provider->BeginStartAdapter(Adapter);
    assert(Start && Start.Value.Sequence == 2);
    assert(Provider->CompleteStartAdapter(Adapter, true) == Status::Success);

    const auto First = Provider->QueueSrb(Adapter, 0x6300, 1);
    const auto Second = Provider->QueueSrb(Adapter, 0x6400, 2);
    assert(First && Second);
    assert(Provider->QueueSrb(Adapter, 0x6500, 2).Code == Status::Duplicate);
    const auto Dispatch = Provider->DispatchNextSrb(Adapter);
    assert(Dispatch && Dispatch.Value.Srb == First.Value && Dispatch.Value.Callback.Sequence == 3);

    const auto Saved = Provider->Snapshot();
    StorportProvider Restored(Validator);
    assert(Restored.Restore(Saved) == Status::Success && Restored.Snapshot() == Saved);
    auto Corrupt = Saved;
    Corrupt.Adapters.begin()->second.PendingSrbs.push_back(First.Value);
    assert(Restored.Restore(Corrupt) == Status::CorruptSnapshot);

    const auto Cancel = Provider->CancelSrb(Second.Value);
    assert(Cancel && Cancel.Value && Cancel.Value->Sequence == 4);
    assert(Provider->CompleteSrb(First.Value, 0) == Status::Success);
    assert(Provider->CompleteSrb(First.Value, 0) == Status::InvalidState);
    const auto Interrupt = Provider->InvokeInterrupt(Adapter);
    const auto Dpc = Provider->InvokeDpc(Adapter, 0x6500, 0x6600);
    assert(Interrupt && Dpc && Interrupt.Value.Sequence == 5 && Dpc.Value.Sequence == 6);
    const auto Reset = Provider->BeginResetAdapter(Adapter, 0);
    assert(Reset && Reset.Value.Sequence == 7);
    assert(Provider->CompleteResetAdapter(Adapter, true) == Status::Success);
    const auto Stop = Provider->BeginStopAdapter(Adapter);
    assert(Stop && Stop.Value.Sequence == 8);
    assert(Provider->CompleteStopAdapter(Adapter) == Status::Success);
    assert(Provider->RemoveAdapter(Adapter) == Status::Success);
    assert(Provider->RemoveAdapter(Adapter) == Status::InvalidHandle);
    assert(Provider->UnregisterMiniport(Registration.Value) == Status::Success);
}

} // namespace

int main() {
    auto Kmdf = std::make_shared<KmdfProvider>(Validator);
    auto Fltmgr = std::make_shared<FltmgrProvider>(Validator);
    auto Ndis = std::make_shared<NdisProvider>(Validator);
    auto Storport = std::make_shared<StorportProvider>(Validator);

    FrameworkRegistry Registry;
    assert(Registry.Register(Storport) == Status::Success);
    assert(Registry.Register(Ndis) == Status::Success);
    assert(Registry.Register(Kmdf) == Status::Success);
    assert(Registry.Register(Fltmgr) == Status::Success);
    assert(Registry.Register(Ndis) == Status::Duplicate);
    assert(!Registry.Find("missing"));

    KmdfFixture(Kmdf);
    FltmgrFixture(Fltmgr);
    NdisFixture(Ndis);
    StorportFixture(Storport);

    const auto Capabilities = Registry.Capabilities();
    assert(Capabilities.size() == 4);
    assert(Capabilities[0].Provider == "fltmgr" && Capabilities[1].Provider == "kmdf" &&
        Capabilities[2].Provider == "ndis" && Capabilities[3].Provider == "storport");
    const auto Snapshot = Registry.Snapshot();
    Registry.Reset();
    assert(Registry.Restore(Snapshot) == Status::Success);
    assert(Ndis->Snapshot() == std::any_cast<NdisSnapshot>(Snapshot.Providers[2].State));
    assert(Storport->Snapshot() == std::any_cast<StorportSnapshot>(Snapshot.Providers[3].State));
    assert(Registry.Unregister("missing") == Status::InvalidHandle);

    std::puts("framework provider fixtures OK");
    return 0;
}
