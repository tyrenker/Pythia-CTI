# Import all ORM models so SQLAlchemy metadata registers them before create_all().
from pythia.models.actor import ActorTTPMapping, ThreatActor  # noqa: F401
from pythia.models.atlas import AtlasTechnique  # noqa: F401
from pythia.models.attck import AttckTechnique  # noqa: F401
from pythia.models.ioc import IoC  # noqa: F401
from pythia.models.malware import MalwareFamily  # noqa: F401
from pythia.models.report import BusinessImpactBrief, SourceReport  # noqa: F401
from pythia.models.owasp_llm import OwaspLlmItem  # noqa: F401
from pythia.models.rule import DetectionRule  # noqa: F401
from pythia.models.watchlist import Watchlist  # noqa: F401
from pythia.models.sync_log import SyncLog  # noqa: F401
from pythia.models.intel_feed import IntelFeedSource, IntelFeedArticle  # noqa: F401
from pythia.models.hunt import HuntSession, HuntObservation, HuntNote, HuntDraftDetection  # noqa: F401
