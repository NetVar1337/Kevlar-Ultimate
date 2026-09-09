#include "io_fuzzer.h"

#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <set>

namespace Kevlar::Fuzz {
namespace {
constexpr std::uint64_t kOffset = 14695981039346656037ull, kPrime = 1099511628211ull;
void Byte(std::uint64_t& H, std::uint8_t V) noexcept { H = (H ^ V) * kPrime; }
void U64(std::uint64_t& H, std::uint64_t V) noexcept { for (unsigned I=0; I<8; ++I) Byte(H, static_cast<std::uint8_t>(V >> (I*8))); }
void Text(std::uint64_t& H, const std::string& S) noexcept { U64(H,S.size()); for (unsigned char C:S) Byte(H,C); }
void Loc(std::uint64_t& H, const Coverage::ModuleLocation& L) noexcept { Text(H,L.Module); U64(H,L.Rva); }
bool ValidCoverage(const Coverage::CoverageSnapshot& C) {
    std::set<Coverage::Edge> Seen;
    for (const auto& R:C.Edges) if (!R.Hits || !Coverage::EdgeCoverage::IsValid(R.Key.From) || !Coverage::EdgeCoverage::IsValid(R.Key.To) || !Seen.insert(R.Key).second) return false;
    return true;
}
bool ValidResult(const ExecutionResult& R) {
    if (!ValidCoverage(R.Coverage)) return false;
    if (R.Outcome==ExecutionOutcome::Crash) return R.Crash && !R.Hang && Coverage::EdgeCoverage::IsValid(R.Crash->Fault);
    if (R.Outcome==ExecutionOutcome::Hang) return R.Hang && !R.Crash && Coverage::EdgeCoverage::IsValid(R.Hang->LastProgress) && !R.Hang->WaitClass.empty();
    return !R.Crash && !R.Hang;
}
std::size_t Cost(const FuzzInput& I) { return I.Buffer.size()+12; }
}

std::uint64_t StableInputId(const FuzzInput& I) noexcept { std::uint64_t H=kOffset; Byte(H,static_cast<std::uint8_t>(I.Kind)); U64(H,I.IoctlCode); Byte(H,I.MajorFunction); Byte(H,I.MinorFunction); U64(H,I.OutputBufferLength); U64(H,I.Buffer.size()); for(auto V:I.Buffer) Byte(H,V); return H; }
std::uint64_t StableCrashId(const CrashSignature& S) noexcept { std::uint64_t H=kOffset; U64(H,S.ExceptionCode); Loc(H,S.Fault); U64(H,S.Stack.size()); for(const auto& L:S.Stack) Loc(H,L); return H; }
std::uint64_t StableHangId(const HangSignature& S) noexcept { std::uint64_t H=kOffset; Loc(H,S.LastProgress); Text(H,S.WaitClass); U64(H,S.ProgressToken); return H; }

IoMutator::IoMutator(std::uint64_t Seed,std::size_t Max,std::vector<std::vector<std::uint8_t>> Dict):Seed_(Seed),State_(Seed?Seed:0x9e3779b97f4a7c15ull),MaximumInputBytes_(Max),Dictionary_(std::move(Dict)){ Dictionary_.erase(std::remove_if(Dictionary_.begin(),Dictionary_.end(),[&](const auto& V){return V.empty()||V.size()>Max;}),Dictionary_.end()); }
std::uint64_t IoMutator::Next() noexcept { State_^=State_>>12; State_^=State_<<25; State_^=State_>>27; return State_*2685821657736338717ull; }
std::size_t IoMutator::Bounded(std::size_t L) noexcept { return L?static_cast<std::size_t>(Next()%L):0; }
MutationStrategy IoMutator::ChooseStrategy(const FuzzInput& B,std::span<const FuzzInput> D) noexcept { std::array<MutationStrategy,9> A{MutationStrategy::FlipBit,MutationStrategy::ReplaceByte,MutationStrategy::InterestingInteger,MutationStrategy::InsertBytes,MutationStrategy::EraseBytes,MutationStrategy::Splice,MutationStrategy::DictionaryOverwrite,MutationStrategy::MutateIoctlCode,MutationStrategy::MutateIrpFunction}; for(;;){auto S=A[Bounded(A.size())]; if((S==MutationStrategy::FlipBit||S==MutationStrategy::ReplaceByte||S==MutationStrategy::EraseBytes)&&B.Buffer.empty())continue; if(S==MutationStrategy::Splice&&D.empty())continue; if(S==MutationStrategy::DictionaryOverwrite&&Dictionary_.empty())continue; return S;} }
std::optional<FuzzInput> IoMutator::Replay(const FuzzInput& B,const MutationRecord& M,std::size_t Max){ FuzzInput R=B; if(B.Buffer.size()>Max)return std::nullopt; auto O=static_cast<std::size_t>(M.Offset),L=static_cast<std::size_t>(M.Length); switch(M.Strategy){
case MutationStrategy::FlipBit: if(O>=R.Buffer.size()||M.Value>7)return std::nullopt; R.Buffer[O]^=static_cast<std::uint8_t>(1u<<M.Value); break;
case MutationStrategy::ReplaceByte: if(O>=R.Buffer.size()||M.Value>255)return std::nullopt; R.Buffer[O]=static_cast<std::uint8_t>(M.Value); break;
case MutationStrategy::InterestingInteger: if(!L||L>8||O>Max-L)return std::nullopt; if(R.Buffer.size()<O+L)R.Buffer.resize(O+L); for(std::size_t I=0;I<L;++I)R.Buffer[O+I]=static_cast<std::uint8_t>(M.Value>>(I*8)); break;
case MutationStrategy::InsertBytes: if(O>R.Buffer.size()||M.Payload.size()>Max-R.Buffer.size())return std::nullopt; R.Buffer.insert(R.Buffer.begin()+O,M.Payload.begin(),M.Payload.end()); break;
case MutationStrategy::EraseBytes: if(O>R.Buffer.size()||L>R.Buffer.size()-O)return std::nullopt; R.Buffer.erase(R.Buffer.begin()+O,R.Buffer.begin()+O+L); break;
case MutationStrategy::Splice: if(O>R.Buffer.size()||L>R.Buffer.size()-O||M.Payload.size()>Max-(R.Buffer.size()-L))return std::nullopt; R.Buffer.erase(R.Buffer.begin()+O,R.Buffer.begin()+O+L); R.Buffer.insert(R.Buffer.begin()+O,M.Payload.begin(),M.Payload.end()); break;
case MutationStrategy::DictionaryOverwrite: if(O>Max||M.Payload.size()>Max-O)return std::nullopt; if(R.Buffer.size()<O+M.Payload.size())R.Buffer.resize(O+M.Payload.size()); std::copy(M.Payload.begin(),M.Payload.end(),R.Buffer.begin()+O); break;
case MutationStrategy::MutateIoctlCode: R.IoctlCode=static_cast<std::uint32_t>(M.Value); break;
case MutationStrategy::MutateIrpFunction: R.MajorFunction=static_cast<std::uint8_t>(M.Value); R.MinorFunction=static_cast<std::uint8_t>(M.Value>>8); break;} return R; }
MutatedInput IoMutator::Mutate(const FuzzInput& B,std::span<const FuzzInput> D){ std::scoped_lock L(Mutex_); MutationRecord M; M.Strategy=ChooseStrategy(B,D); switch(M.Strategy){case MutationStrategy::FlipBit:M.Offset=Bounded(B.Buffer.size());M.Value=Bounded(8);break;case MutationStrategy::ReplaceByte:M.Offset=Bounded(B.Buffer.size());M.Value=Next()&255;break;case MutationStrategy::InterestingInteger:{static constexpr std::array<std::uint64_t,8> V{0,1,0x7f,0x80,0xff,0x7fff,0x80000000ull,~0ull};M.Length=std::array<std::size_t,4>{1,2,4,8}[Bounded(4)];if(M.Length>MaximumInputBytes_)M.Length=1;M.Offset=Bounded(std::min(MaximumInputBytes_-M.Length,B.Buffer.size())+1);M.Value=V[Bounded(V.size())];break;}case MutationStrategy::InsertBytes:{auto N=std::min<std::size_t>(1+Bounded(8),MaximumInputBytes_-std::min(MaximumInputBytes_,B.Buffer.size()));M.Offset=Bounded(B.Buffer.size()+1);M.Payload.resize(N);for(auto&X:M.Payload)X=static_cast<std::uint8_t>(Next());break;}case MutationStrategy::EraseBytes:M.Offset=Bounded(B.Buffer.size());M.Length=1+Bounded(B.Buffer.size()-M.Offset);break;case MutationStrategy::Splice:{const auto& X=D[Bounded(D.size())].Buffer;M.Offset=Bounded(B.Buffer.size()+1);M.Length=M.Offset<B.Buffer.size()?Bounded(B.Buffer.size()-M.Offset+1):0;auto N=std::min<std::size_t>(X.size(),MaximumInputBytes_-(B.Buffer.size()-M.Length));auto S=Bounded(X.size()-N+1);M.Payload.assign(X.begin()+S,X.begin()+S+N);break;}case MutationStrategy::DictionaryOverwrite:M.Payload=Dictionary_[Bounded(Dictionary_.size())];M.Offset=Bounded(std::min(B.Buffer.size(),MaximumInputBytes_-M.Payload.size())+1);break;case MutationStrategy::MutateIoctlCode:M.Value=(B.IoctlCode^(1u<<Bounded(32)));break;case MutationStrategy::MutateIrpFunction:M.Value=Bounded(0x1c)|(Bounded(256)<<8);break;} auto R=Replay(B,M,MaximumInputBytes_); return {R?std::move(*R):B,std::move(M)}; }
MutatorSnapshot IoMutator::Snapshot() const { std::scoped_lock L(Mutex_); return {Seed_,State_,MaximumInputBytes_,Dictionary_}; }
bool IoMutator::Restore(const MutatorSnapshot& S){ if(!S.State||!S.MaximumInputBytes)return false; for(const auto& D:S.Dictionary)if(D.empty()||D.size()>S.MaximumInputBytes)return false; std::scoped_lock L(Mutex_);Seed_=S.Seed;State_=S.State;MaximumInputBytes_=S.MaximumInputBytes;Dictionary_=S.Dictionary;return true; }

AdmissionDecision FuzzCorpus::Admit(const FuzzInput& I,const ExecutionResult& R){ AdmissionDecision D; if(!ValidResult(R)){D.Valid=false;return D;} std::scoped_lock L(Mutex_);std::set<Coverage::Edge> E;std::set<CrashSignature>C;std::set<HangSignature>H;for(const auto& X:State_.Entries){for(const auto& Z:X.Result.Coverage.Edges)E.insert(Z.Key);if(X.Result.Crash)C.insert(*X.Result.Crash);if(X.Result.Hang)H.insert(*X.Result.Hang);}for(const auto& X:R.Coverage.Edges)if(!E.contains(X.Key))++D.NewEdgeCount;D.NewCoverage=D.NewEdgeCount!=0;D.NewCrash=R.Crash&&!C.contains(*R.Crash);D.NewHang=R.Hang&&!H.contains(*R.Hang);D.Admitted=D.NewCoverage||D.NewCrash||D.NewHang;if(D.Admitted)State_.Entries.push_back({I,R,State_.NextSequence++});return D; }
std::vector<CorpusEntry> FuzzCorpus::Entries() const {std::scoped_lock L(Mutex_);return State_.Entries;} std::size_t FuzzCorpus::Size() const{std::scoped_lock L(Mutex_);return State_.Entries.size();} CorpusSnapshot FuzzCorpus::Snapshot()const{std::scoped_lock L(Mutex_);return State_;}
bool FuzzCorpus::Restore(const CorpusSnapshot&S){if(!S.NextSequence)return false;std::set<std::uint64_t> Q;for(const auto&E:S.Entries)if(!E.Sequence||E.Sequence>=S.NextSequence||!Q.insert(E.Sequence).second||!ValidResult(E.Result))return false;std::scoped_lock L(Mutex_);State_=S;return true;}
std::size_t FuzzCorpus::Minimize(){std::scoped_lock L(Mutex_);std::set<Coverage::Edge>E;std::set<CrashSignature>C;std::set<HangSignature>H;for(const auto&X:State_.Entries){for(const auto&R:X.Result.Coverage.Edges)E.insert(R.Key);if(X.Result.Crash)C.insert(*X.Result.Crash);if(X.Result.Hang)H.insert(*X.Result.Hang);}std::vector<CorpusEntry>K;std::vector<bool>U(State_.Entries.size());while(!E.empty()||!C.empty()||!H.empty()){std::size_t Best=State_.Entries.size(),Score=0;for(std::size_t I=0;I<State_.Entries.size();++I)if(!U[I]){const auto&X=State_.Entries[I];std::size_t S=0;for(const auto&R:X.Result.Coverage.Edges)S+=E.contains(R.Key);if(X.Result.Crash)S+=C.contains(*X.Result.Crash);if(X.Result.Hang)S+=H.contains(*X.Result.Hang);if(S>Score||(S==Score&&S&&(Best==State_.Entries.size()||Cost(X.Input)<Cost(State_.Entries[Best].Input)||(Cost(X.Input)==Cost(State_.Entries[Best].Input)&&StableInputId(X.Input)<StableInputId(State_.Entries[Best].Input))))){Best=I;Score=S;}}if(!Score)break;U[Best]=true;const auto&X=State_.Entries[Best];K.push_back(X);for(const auto&R:X.Result.Coverage.Edges)E.erase(R.Key);if(X.Result.Crash)C.erase(*X.Result.Crash);if(X.Result.Hang)H.erase(*X.Result.Hang);}auto Removed=State_.Entries.size()-K.size();std::sort(K.begin(),K.end(),[](const auto&A,const auto&B){return A.Sequence<B.Sequence;});State_.Entries=std::move(K);return Removed;}
void FuzzCorpus::Clear(){std::scoped_lock L(Mutex_);State_={};}

IoFuzzCampaign::IoFuzzCampaign(std::uint64_t S,std::vector<FuzzInput> Seeds,std::size_t M,std::vector<std::vector<std::uint8_t>>D):Seed_(S),Seeds_(std::move(Seeds)),Mutator_(S,M,std::move(D)){}
CampaignReport IoFuzzCampaign::Run(std::size_t N,const ExecutionCallback& X){CampaignReport R{Seed_,{}};if(!X)return R;std::scoped_lock L(Mutex_);R.Iterations.reserve(N);for(std::size_t I=0;I<N&&!Seeds_.empty();++I){auto Entries=Corpus_.Entries();std::vector<FuzzInput> Pool=Seeds_;for(const auto&E:Entries)Pool.push_back(E.Input);auto Index=static_cast<std::size_t>(NextIteration_%Pool.size());auto M=Mutator_.Mutate(Pool[Index],Pool);auto Result=X(M.Input,NextIteration_);auto A=Corpus_.Admit(M.Input,Result);R.Iterations.push_back({NextIteration_,StableInputId(Pool[Index]),std::move(M),std::move(Result),A});++NextIteration_;}return R;}
CampaignSnapshot IoFuzzCampaign::Snapshot()const{std::scoped_lock L(Mutex_);return{Seed_,NextIteration_,Seeds_,Mutator_.Snapshot(),Corpus_.Snapshot()};}
bool IoFuzzCampaign::Restore(const CampaignSnapshot&S){if(S.Seed!=S.Mutator.Seed)return false;std::scoped_lock L(Mutex_);if(!Mutator_.Restore(S.Mutator)||!Corpus_.Restore(S.Corpus))return false;Seed_=S.Seed;NextIteration_=S.NextIteration;Seeds_=S.Seeds;return true;}
std::vector<CorpusEntry> IoFuzzCampaign::CorpusEntries()const{return Corpus_.Entries();}
} // namespace Kevlar::Fuzz
