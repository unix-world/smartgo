const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/graphqlMode.js","assets/monaco-editor.js","assets/index.js","assets/index.css","assets/mouseTarget.js","assets/monaco-editor.css"])))=>i.map(i=>d[i]);
var __defProp = Object.defineProperty;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
import { _ as __vitePreload } from "./index.js";
import { E as Emitter, l as languages } from "./monaco-editor.js";
import "./mouseTarget.js";
class MonacoGraphQLAPI {
  constructor({ languageId, schemas, modeConfiguration, formattingOptions, diagnosticSettings, completionSettings }) {
    __publicField(this, "_onDidChange", new Emitter());
    __publicField(this, "_formattingOptions");
    __publicField(this, "_modeConfiguration");
    __publicField(this, "_diagnosticSettings");
    __publicField(this, "_completionSettings");
    __publicField(this, "_schemas", null);
    __publicField(this, "_schemasById", /* @__PURE__ */ Object.create(null));
    __publicField(this, "_languageId");
    __publicField(this, "_externalFragmentDefinitions");
    this._languageId = languageId;
    if (schemas) {
      this.setSchemaConfig(schemas);
    }
    this._modeConfiguration = modeConfiguration;
    this._completionSettings = completionSettings;
    this._diagnosticSettings = diagnosticSettings;
    this._formattingOptions = formattingOptions;
  }
  get onDidChange() {
    return this._onDidChange.event;
  }
  get languageId() {
    return this._languageId;
  }
  get modeConfiguration() {
    return this._modeConfiguration;
  }
  get schemas() {
    return this._schemas;
  }
  schemasById() {
    return this._schemasById;
  }
  get formattingOptions() {
    return this._formattingOptions;
  }
  get diagnosticSettings() {
    return this._diagnosticSettings;
  }
  get completionSettings() {
    return {
      ...this._completionSettings,
      fillLeafsOnComplete: this._completionSettings.__experimental__fillLeafsOnComplete ?? this._completionSettings.fillLeafsOnComplete
    };
  }
  get externalFragmentDefinitions() {
    return this._externalFragmentDefinitions;
  }
  setSchemaConfig(schemas) {
    this._schemas = schemas;
    this._schemasById = schemas.reduce((result, schema) => {
      result[schema.uri] = schema;
      return result;
    }, /* @__PURE__ */ Object.create(null));
    this._onDidChange.fire(this);
  }
  setExternalFragmentDefinitions(externalFragmentDefinitions) {
    this._externalFragmentDefinitions = externalFragmentDefinitions;
  }
  setModeConfiguration(modeConfiguration) {
    this._modeConfiguration = modeConfiguration;
    this._onDidChange.fire(this);
  }
  setFormattingOptions(formattingOptions) {
    this._formattingOptions = formattingOptions;
    this._onDidChange.fire(this);
  }
  setDiagnosticSettings(diagnosticSettings) {
    this._diagnosticSettings = diagnosticSettings;
    this._onDidChange.fire(this);
  }
  setCompletionSettings(completionSettings) {
    this._completionSettings = completionSettings;
    this._onDidChange.fire(this);
  }
}
function create(languageId, config) {
  if (!config) {
    return new MonacoGraphQLAPI({
      languageId,
      schemas: [],
      formattingOptions: formattingDefaults,
      modeConfiguration: modeConfigurationDefault,
      diagnosticSettings: diagnosticSettingDefault,
      completionSettings: completionSettingDefault
    });
  }
  const { schemas, formattingOptions, modeConfiguration, diagnosticSettings, completionSettings } = config;
  return new MonacoGraphQLAPI({
    languageId,
    schemas,
    formattingOptions: {
      ...formattingDefaults,
      ...formattingOptions,
      prettierConfig: {
        ...formattingDefaults.prettierConfig,
        ...formattingOptions == null ? void 0 : formattingOptions.prettierConfig
      }
    },
    modeConfiguration: {
      ...modeConfigurationDefault,
      ...modeConfiguration
    },
    diagnosticSettings: {
      ...diagnosticSettingDefault,
      ...diagnosticSettings
    },
    completionSettings: {
      ...completionSettingDefault,
      ...completionSettings
    }
  });
}
const modeConfigurationDefault = {
  documentFormattingEdits: true,
  documentRangeFormattingEdits: false,
  completionItems: true,
  hovers: true,
  documentSymbols: false,
  tokens: false,
  colors: false,
  foldingRanges: false,
  diagnostics: true,
  selectionRanges: false
};
const formattingDefaults = {
  prettierConfig: {
    tabWidth: 2
  }
};
const diagnosticSettingDefault = {
  jsonDiagnosticSettings: {
    schemaValidation: "error"
  }
};
const completionSettingDefault = {
  __experimental__fillLeafsOnComplete: false
};
const LANGUAGE_ID = "graphql";
let api;
function initializeMode(config) {
  if (!api) {
    api = create(LANGUAGE_ID, config);
    languages.graphql = { api };
    void getMode().then((mode) => mode.setupMode(api));
  }
  return api;
}
function getMode() {
  return __vitePreload(() => import("./graphqlMode.js"), true ? __vite__mapDeps([0,1,2,3,4,5]) : void 0);
}
export {
  LANGUAGE_ID,
  initializeMode
};
