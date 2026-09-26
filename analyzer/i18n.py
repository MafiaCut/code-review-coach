"""
Internationalisation (i18n) for the Code Review Coach.

Supported languages: "en" (English, default), "es" (Spanish).

All human-readable output is translated here. Analysis logic (regex patterns)
is language-agnostic and unchanged. Adding a new language only requires adding
a new dict entry in each section below.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

SUPPORTED_LANGS = ("en", "es")
DEFAULT_LANG = "en"


def resolve_lang(lang: str) -> str:
    """Normalise and validate a language code. Falls back to 'en'."""
    code = (lang or "en").lower().strip()
    return code if code in SUPPORTED_LANGS else DEFAULT_LANG


# ── Category labels ──────────────────────────────────────────────

CATEGORY_LABELS: Dict[str, Dict[str, str]] = {
    "en": {
        "secrets":                   "Exposed Secret",
        "unsafe_input":              "Unsafe Input",
        "error_handling":            "Error Handling",
        "likely_bug":                "Likely Bug",
        "weak_tests":                "Weak Tests",
        "logging_sensitive":         "Sensitive Logging",
        "dangerous_deserialization": "Dangerous Deserialization",
        "path_traversal":            "Path Traversal",
        "insecure_dependency":       "Insecure Dependency",
    },
    "es": {
        "secrets":                   "Secreto expuesto",
        "unsafe_input":              "Entrada no segura",
        "error_handling":            "Manejo de errores",
        "likely_bug":                "Posible error",
        "weak_tests":                "Pruebas debiles",
        "logging_sensitive":         "Datos sensibles en logs",
        "dangerous_deserialization": "Deserializacion peligrosa",
        "path_traversal":            "Traversal de rutas",
        "insecure_dependency":       "Dependencia insegura",
    },
}


# ── Risk templates (summary "Main Risks") ───────────────────────

RISK_TEMPLATES: Dict[str, Dict[str, str]] = {
    "en": {
        "secrets":                   "One or more hardcoded credentials were found. These will be permanently stored in git history.",
        "unsafe_input":              "Unsafe input handling patterns detected that may allow injection or code execution attacks.",
        "error_handling":            "Error handling gaps that could cause silent failures or expose internal details to callers.",
        "likely_bug":                "Code patterns that are likely to produce incorrect behavior at runtime.",
        "weak_tests":                "Test coverage gaps that reduce confidence in the correctness of the change.",
        "logging_sensitive":         "Sensitive variable values (passwords, tokens) may be written to log files or stdout.",
        "dangerous_deserialization": "Unsafe deserialization can execute attacker-controlled code on the server.",
        "path_traversal":            "File operations with user-controlled paths may expose or overwrite arbitrary files.",
        "insecure_dependency":       "One or more dependencies are pinned to versions with known CVEs.",
    },
    "es": {
        "secrets":                   "Se encontraron credenciales en el codigo fuente. Quedaran almacenadas permanentemente en el historial de git.",
        "unsafe_input":              "Se detectaron patrones de manejo inseguro de entradas que pueden permitir inyeccion o ejecucion de codigo.",
        "error_handling":            "Hay fallos en el manejo de errores que pueden causar errores silenciosos o exponer detalles internos.",
        "likely_bug":                "Se detectaron patrones de codigo que probablemente produzcan comportamiento incorrecto en tiempo de ejecucion.",
        "weak_tests":                "Hay brechas en la cobertura de pruebas que reducen la confianza en la correccion del cambio.",
        "logging_sensitive":         "Valores de variables sensibles (contrasenas, tokens) pueden estar siendo escritos en logs o salida estandar.",
        "dangerous_deserialization": "La deserializacion insegura puede ejecutar codigo controlado por un atacante en el servidor.",
        "path_traversal":            "Las operaciones de archivos con rutas controladas por el usuario pueden exponer o sobrescribir archivos arbitrarios.",
        "insecure_dependency":       "Una o mas dependencias estan fijadas a versiones con CVEs conocidos.",
    },
}


# ── Step templates (summary "Next Steps") ───────────────────────

STEP_TEMPLATES: Dict[str, Dict[str, str]] = {
    "en": {
        "secrets":                   "Rotate any exposed credentials immediately, then remove them from source and git history (git filter-repo).",
        "unsafe_input":              "Replace unsafe constructs with safe alternatives before merging (see individual findings).",
        "error_handling":            "Add specific exception handling and verify error paths are tested.",
        "likely_bug":                "Review flagged lines carefully; add regression tests to prevent reintroduction.",
        "weak_tests":                "Implement the missing tests and ensure edge cases are covered.",
        "logging_sensitive":         "Remove sensitive values from log statements; use redacted placeholders if logging is needed.",
        "dangerous_deserialization": "Replace pickle/unsafe YAML with safe alternatives (JSON, yaml.safe_load).",
        "path_traversal":            "Validate and canonicalize all user-supplied paths before any file operation.",
        "insecure_dependency":       "Upgrade flagged dependencies to the minimum safe versions listed in the findings.",
    },
    "es": {
        "secrets":                   "Rota las credenciales expuestas de inmediato y eliminaias del codigo fuente y del historial de git (git filter-repo).",
        "unsafe_input":              "Reemplaza los constructos inseguros por alternativas seguras antes de fusionar (ver hallazgos individuales).",
        "error_handling":            "Anade manejo especifico de excepciones y verifica que las rutas de error esten probadas.",
        "likely_bug":                "Revisa cuidadosamente las lineas marcadas; anade pruebas de regresion para evitar reintroduccion.",
        "weak_tests":                "Implementa las pruebas faltantes y asegurate de cubrir los casos limite.",
        "logging_sensitive":         "Elimina los valores sensibles de los registros; usa marcadores redactados si el registro es necesario.",
        "dangerous_deserialization": "Reemplaza pickle/YAML inseguro por alternativas seguras (JSON, yaml.safe_load).",
        "path_traversal":            "Valida y canonicaliza todas las rutas suministradas por el usuario antes de cualquier operacion con archivos.",
        "insecure_dependency":       "Actualiza las dependencias marcadas a las versiones minimas seguras indicadas en los hallazgos.",
    },
}


@dataclass(frozen=True)
class CategoryMetadata:
    """All localized presentation metadata for an analysis category."""

    category_id: str
    labels: Dict[str, str]
    risks: Dict[str, str]
    next_steps: Dict[str, str]


CATEGORY_CATALOG: Dict[str, CategoryMetadata] = {
    category_id: CategoryMetadata(
        category_id=category_id,
        labels={lang: CATEGORY_LABELS[lang][category_id] for lang in SUPPORTED_LANGS},
        risks={lang: RISK_TEMPLATES[lang][category_id] for lang in SUPPORTED_LANGS},
        next_steps={lang: STEP_TEMPLATES[lang][category_id] for lang in SUPPORTED_LANGS},
    )
    for category_id in CATEGORY_LABELS[DEFAULT_LANG]
}


def category_label(category: str, lang: str = DEFAULT_LANG) -> str:
    """Return a localized category label, falling back to the category id."""
    metadata = CATEGORY_CATALOG.get(category)
    if metadata is None:
        return category
    resolved = resolve_lang(lang)
    return metadata.labels.get(resolved, metadata.labels[DEFAULT_LANG])


def category_risk(category: str, lang: str = DEFAULT_LANG) -> Optional[str]:
    """Return the localized summary risk for a category."""
    metadata = CATEGORY_CATALOG.get(category)
    if metadata is None:
        return None
    resolved = resolve_lang(lang)
    return metadata.risks.get(resolved, metadata.risks[DEFAULT_LANG])


def category_next_step(category: str, lang: str = DEFAULT_LANG) -> Optional[str]:
    """Return the localized next step for a category."""
    metadata = CATEGORY_CATALOG.get(category)
    if metadata is None:
        return None
    resolved = resolve_lang(lang)
    return metadata.next_steps.get(resolved, metadata.next_steps[DEFAULT_LANG])


# ── Recommendation reasons ───────────────────────────────────────

REC_REASONS: Dict[str, Dict[str, str]] = {
    "en": {
        "critical": "{n} critical finding(s) must be resolved before this change can be merged.",
        "high":     "{n} high-severity finding(s) require attention before merging.",
        "medium":   "{n} medium-severity finding(s) were found. Discuss with the author before merging.",
        "low":      "Only low/info findings. The change looks safe but address the notes before the next release.",
        "none":     "No issues detected in the analyzed lines. Standard review applies.",
    },
    "es": {
        "critical": "{n} hallazgo(s) critico(s) deben resolverse antes de que este cambio pueda fusionarse.",
        "high":     "{n} hallazgo(s) de severidad alta requieren atencion antes de fusionar.",
        "medium":   "Se encontraron {n} hallazgo(s) de severidad media. Discute con el autor antes de fusionar.",
        "low":      "Solo se encontraron hallazgos de severidad baja/informativa. El cambio parece seguro; aborda las notas antes del proximo lanzamiento.",
        "none":     "No se detectaron problemas en las lineas analizadas. Se aplica la revision estandar.",
    },
}

NO_ISSUES: Dict[str, str] = {
    "en": "No significant issues detected in the analyzed lines.",
    "es": "No se detectaron problemas significativos en las lineas analizadas.",
}

NORMAL_REVIEW: Dict[str, str] = {
    "en": "Proceed with normal review. Verify that test coverage is adequate.",
    "es": "Continua con la revision normal. Verifica que la cobertura de pruebas sea adecuada.",
}


# ── Per-finding translations ─────────────────────────────────────
# List of (english_keyword, es_explanation, es_fix) per category.
# The first matching keyword (case-insensitive substring of the English explanation) wins.

_FINDING_ES: Dict[str, list] = {
    "secrets": [
        (
            "password",
            "Se detecto una contrasena en texto plano. Las credenciales confirmadas en el control de versiones quedan expuestas permanentemente en el historial de git, incluso despues de ser eliminadas.",
            "Elimina el valor literal. Carga los secretos desde variables de entorno (os.environ / process.env) o un gestor de secretos (p. ej. AWS Secrets Manager, HashiCorp Vault).",
        ),
        (
            "API key",
            "Se detecto una clave de API en texto plano. Las credenciales confirmadas quedan expuestas permanentemente en el historial de git.",
            "Elimina el valor literal. Carga los secretos desde variables de entorno o un gestor de secretos.",
        ),
        (
            "AWS",
            "Se detecto un patron de ID de clave de acceso de AWS. Las credenciales confirmadas quedan expuestas permanentemente en el historial de git.",
            "Elimina el valor literal. Usa variables de entorno o roles IAM con credenciales temporales.",
        ),
        (
            "Connection string",
            "Se detecto una cadena de conexion con contrasena embebida. Las credenciales confirmadas quedan expuestas permanentemente en el historial de git.",
            "Elimina el valor literal. Usa variables de entorno o un gestor de secretos.",
        ),
        (
            "High-entropy",
            "Se detecto una cadena de alta entropia. Esta cadena tiene el perfil estadistico de un secreto generado, clave de API o token, independientemente del nombre de la variable.",
            "Si es una credencial real, eliminala y usa una variable de entorno o gestor de secretos. Si es intencional (p. ej. un vector de prueba), anade un comentario `# noqa: secrets` para suprimir.",
        ),
        (
            "token",
            "Se detecto un token o credencial en texto plano. Las credenciales confirmadas quedan expuestas permanentemente en el historial de git.",
            "Elimina el valor literal. Carga los secretos desde variables de entorno o un gestor de secretos.",
        ),
        (
            "credentials",
            "Se detectaron credenciales en texto plano. Las credenciales confirmadas quedan expuestas permanentemente en el historial de git.",
            "Elimina el valor literal. Carga los secretos desde variables de entorno o un gestor de secretos.",
        ),
    ],
    "unsafe_input": [
        (
            "eval()",
            "Uso de eval() con datos potencialmente no confiables. eval() ejecuta codigo arbitrario.",
            "Reemplaza eval() con una alternativa segura (ast.literal_eval para estructuras de datos o un analizador explicito).",
        ),
        (
            "exec()",
            "Uso de exec() con datos potencialmente no confiables. exec() ejecuta codigo arbitrario.",
            "Evita exec(). Refactoriza la logica para usar despacho basado en datos.",
        ),
        (
            "shell=True",
            "subprocess llamado con shell=True - susceptible a inyeccion de shell.",
            "Pasa una lista de argumentos en lugar de una cadena y establece shell=False. Valida cualquier parte suministrada por el usuario.",
        ),
        (
            "os.system()",
            "os.system() pasa la entrada directamente al shell.",
            "Usa subprocess.run() con una lista de argumentos y shell=False.",
        ),
        (
            "interpolated",
            "Datos controlados por el usuario interpolados en una cadena sin sanitizacion.",
            "Valida y escapa la entrada del usuario antes de incluirla en cadenas, especialmente consultas SQL, plantillas HTML o comandos de shell.",
        ),
        (
            "SQL injection",
            "Posible inyeccion SQL - la consulta se construye con concatenacion de cadenas.",
            "Usa consultas parametrizadas: cursor.execute('SELECT ... WHERE id = %s', (user_id,)).",
        ),
        (
            "innerHTML",
            "Asignacion directa a innerHTML - posible vector XSS.",
            "Usa textContent para texto plano o sanitiza con DOMPurify antes de asignar innerHTML.",
        ),
        (
            "document.write",
            "document.write() puede sobrescribir la pagina y habilita XSS.",
            "Usa metodos de manipulacion del DOM (createElement, appendChild) en su lugar.",
        ),
        (
            "Shell command",
            "Comando de shell construido con concatenacion de cadenas - riesgo de inyeccion.",
            "Usa execFile() con un comando fijo y un array de argumentos; nunca concatenes entrada del usuario en una cadena de shell.",
        ),
        (
            "multi-line",
            "Posible inyeccion SQL - la consulta parece construirse mediante concatenacion de cadenas en multiples lineas.",
            "Usa consultas parametrizadas: cursor.execute('SELECT ... WHERE id = %s', (user_id,)).",
        ),
    ],
    "error_handling": [
        (
            "Bare",
            "El `except:` desnudo captura todas las excepciones incluyendo KeyboardInterrupt y SystemExit, dificultando la terminacion del programa y enmascarando errores reales.",
            "Captura excepciones especificas: `except (ValueError, IOError) as e:`. Registra o vuelve a lanzar excepciones inesperadas.",
        ),
        (
            "overly broad",
            "`except Exception:` es demasiado amplio y puede ocultar errores de programacion.",
            "Captura el tipo de excepcion mas especifico esperado en este sitio de llamada.",
        ),
        (
            "HTTP response",
            "El estado de la respuesta HTTP no se verifica. Una respuesta 4xx/5xx sera ignorada silenciosamente.",
            "Llama a response.raise_for_status() inmediatamente despues de la solicitud, o verifica response.ok antes de procesar el cuerpo.",
        ),
        (
            "Empty catch",
            "El bloque catch vacio silencia excepciones. Los errores seran invisibles en tiempo de ejecucion.",
            "Registra el error (`console.error(e)`) como minimo, o propagalo con `throw e`. Maneja el caso de fallo explicitamente.",
        ),
    ],
    "likely_bug": [
        (
            "identity",
            "`is` comprueba la identidad del objeto, no la igualdad. Puede comportarse de forma inesperada con valores no singleton.",
            "Usa `==` para comparaciones de igualdad. Reserva `is` para comprobaciones de None.",
        ),
        (
            "Mutable default",
            "El argumento predeterminado mutable se comparte entre todas las llamadas. Las mutaciones en una llamada afectaran llamadas posteriores de forma inesperada.",
            "Usa `None` como valor predeterminado e inicializa dentro de la funcion: `if param is None: param = []`",
        ),
        (
            "floating-point",
            "La comparacion directa de igualdad en punto flotante no es confiable debido a errores de redondeo.",
            "Usa `math.isclose(a, b)` o compara con una tolerancia: `abs(a - b) < 1e-9`.",
        ),
        (
            "coercion",
            "La igualdad debil `==` realiza coercion de tipos que puede producir resultados sorprendentes (p. ej. `0 == ''` es verdadero).",
            "Usa igualdad estricta `===` (y `!==` para la desigualdad).",
        ),
        (
            "swallows",
            "`except: pass` silencia todas las excepciones. Los errores en tiempo de ejecucion seran invisibles.",
            "Como minimo, registra la excepcion. Elimina el try/except si no es posible ninguna recuperacion.",
        ),
    ],
    "weak_tests": [
        (
            "always True",
            "La asercion que siempre es verdadera no comprueba ningun comportamiento real.",
            "Comprueba un valor esperado especifico contra la salida real de la funcion.",
        ),
        (
            "TODO",
            "El comentario TODO indica un caso de prueba que aun no se ha escrito.",
            "Implementa la prueba faltante antes de fusionar.",
        ),
    ],
    "logging_sensitive": [
        (
            "logging",
            "Una llamada de logging o print parece mostrar una variable sensible (contrasena, token, secreto o credencial). Los logs suelen almacenarse en texto plano y son accesibles para equipos de soporte.",
            "Elimina los valores sensibles de la salida de logs. Si necesitas depurar, usa un marcador redactado: `logger.debug('intento auth usuario=%s', username)`. Nunca registres el valor de la credencial.",
        ),
    ],
    "dangerous_deserialization": [
        (
            "pickle",
            "`pickle.loads/load()` deserializa objetos Python arbitrarios y puede ejecutar codigo embebido en el payload. Nunca deserialices datos de una fuente no confiable.",
            "Reemplaza pickle por un formato seguro como JSON o MessagePack. Si se requiere pickle, valida una firma criptografica en el payload antes de deserializar.",
        ),
        (
            "yaml.load",
            "`yaml.load()` sin argumento `Loader=` usa el cargador completo inseguro que puede instanciar objetos Python arbitrarios desde entrada YAML.",
            "Usa `yaml.safe_load(data)` para entrada no confiable, o pasa `Loader=yaml.SafeLoader` explicitamente.",
        ),
        (
            "JSON.parse",
            "`JSON.parse(eval(...))` evalua la cadena como JavaScript antes de analizarla, habilitando la ejecucion de codigo mediante entrada manipulada.",
            "Usa `JSON.parse()` directamente en la cadena sin envolver en eval().",
        ),
    ],
    "path_traversal": [
        (
            "open()",
            "open() se llama directamente con una ruta controlada por el usuario.",
            "Valida y canonicaliza la ruta con os.path.realpath() y confirma que comienza con el directorio base esperado antes de abrir.",
        ),
        (
            "os.path.join()",
            "os.path.join() con un componente controlado por el usuario - riesgo de traversal de rutas.",
            "Usa os.path.realpath() para resolver la ruta final, luego verifica que comienza con el directorio base permitido.",
        ),
        (
            "send_file()",
            "send_file() con nombre de archivo controlado por el usuario - riesgo de revelacion arbitraria de archivos.",
            "Usa flask.send_from_directory() con un directorio fijo y un nombre de archivo sanitizado (werkzeug.utils.secure_filename).",
        ),
        (
            "fs operation",
            "Operacion de sistema de archivos con ruta controlada por el usuario - riesgo de traversal de rutas.",
            "Resuelve y valida la ruta: usa path.resolve() y confirma que comienza con el directorio raiz esperado.",
        ),
        (
            "path.join",
            "path.join(__dirname, entrada_usuario) - riesgo de traversal de rutas.",
            "Sanitiza el segmento suministrado por el usuario (elimina '../' al inicio), luego valida que la ruta resuelta este dentro del directorio esperado.",
        ),
    ],
    "insecure_dependency": [
        (
            "known-vulnerable",
            None,   # Keep original — it contains package name + version
            "Actualiza a la version minima segura. Ejecuta `pip-audit` o `safety check` para analizar todas las dependencias.",
        ),
        (
            "CVE",
            None,
            "Actualiza las dependencias marcadas a las versiones minimas seguras indicadas en los hallazgos.",
        ),
    ],
}


def translate_finding(
    category: str,
    explanation: str,
    recommended_fix: str,
    lang: str,
) -> Tuple[str, str]:
    """
    Return (explanation, recommended_fix) translated to the target language.
    Falls back to the original English strings if no translation matches.
    """
    if lang == "en":
        return explanation, recommended_fix
    translations = _FINDING_ES.get(category, [])
    for keyword, es_expl, es_fix in translations:
        if keyword.lower() in explanation.lower():
            return (
                es_expl if es_expl is not None else explanation,
                es_fix if es_fix is not None else recommended_fix,
            )
    return explanation, recommended_fix


def get_rec_reason(lang: str, level: str, n: int = 0) -> str:
    reasons = REC_REASONS.get(lang, REC_REASONS["en"])
    template = reasons.get(level, reasons["none"])
    return template.replace("{n}", str(n))
