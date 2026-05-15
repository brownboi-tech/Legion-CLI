from pydantic import BaseModel
class TargetRequest(BaseModel): target: str; scope: str = 'scope.yaml'
class JSUrlRequest(TargetRequest): url: str; ai_summary: bool = False
class NucleiRequest(TargetRequest): urls_file: str
class GraphQLRequest(TargetRequest): endpoint: str
class OAuthRequest(TargetRequest): url: str
class IDORPlanRequest(TargetRequest): replay_file: str
class ReportRequest(BaseModel): target: str; finding: str
class ChatRequest(BaseModel): target: str; message: str; scope: str = 'scope.yaml'; session_id: str | None = None
class ChatConfirmRequest(BaseModel): session_id: str
class ScopeFromChatRequest(BaseModel): program: str; message: str
