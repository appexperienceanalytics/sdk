/**
 * CA Wily Introscope(R) Version @@2.0.0.3@@ Build @@4@@
 * @@Copyright (c) 2017 CA. All Rights Reserved.@@
 * @@Introscope(R) is a registered trademark of CA.@@
 */
try {
    if ( typeof BrowserAgent !== 'undefined' ) {
        // Multiple Snippet Insertion
        throw new Error("Detected multiple instances of Browser Agent. Skipping monitoring for this instance.");
    }

    BrowserAgent = {};

    /**
     * This object comprises of Browser Agent global data structures and variables
     * that are accessed in other Browser Agent objects.
     */
    BrowserAgent.globals = {
        init : function () {
            // Here, the page should have loaded. So, set the pageLoadFlag
            BrowserAgent.globals.defaultMetricDefs = BrowserAgent.globals.setDefaultMetricDefs();
            var eum = {};
            eum.schemaVersion = BrowserAgent.jsonUtils.jsonConstants.SCHEMA_VERSION;
            eum.creator = {
                name : BrowserAgent.jsonUtils.jsonConstants.CREATOR_NAME,
                version : BrowserAgent.jsonUtils.jsonConstants.CREATOR_VERSION
            };
            eum.clientInfo = {};
            if ( navigator.userAgent ) {
                eum.clientInfo.userAgent = navigator.userAgent;
            }
            if ( BrowserAgent.globals.browserFingerprint ) {
                eum.clientInfo.fingerPrint = BrowserAgent.globals.browserFingerprint;
            }
            if ( BrowserAgent.globals.platform ) {
                eum.clientInfo.browserType = BrowserAgent.globals.platform;
            }
            if ( BrowserAgent.globals.platformVersion ) {
                eum.clientInfo.browserMajorVersion = BrowserAgent.globals.platformVersion;
            }
            eum.app = { ba : { pages : { pageList : [] } } };
            if ( BrowserAgent.globals.appInfo.id ) {
                eum.app.id = BrowserAgent.globals.appInfo.id;
            }
            if ( BrowserAgent.globals.appInfo.key ) {
                eum.app.key = BrowserAgent.globals.appInfo.key;
            }
            eum.app.version = BrowserAgent.jsonUtils.jsonConstants.APP_VERSION;
            if ( BrowserAgent.globals.appInfo.tenantId ) {
                eum.app.tenantId = BrowserAgent.globals.appInfo.tenantId;
            }
            if ( BrowserAgent.globals.profileInfo ) {
                eum.app.profileInfo = BrowserAgent.globals.profileInfo;
            }
            BrowserAgent.globals.eumJSONShell = eum;
        },
        /**
         * Updates and returns the next sequence number
         * @returns {*}
         */
        getSequenceNum : function () {
            BrowserAgent.globals.sequenceNum += 1;
            return BrowserAgent.globals.sequenceNum;
        },
        /**
         * Returns the next sequence number without incrementing it
         * @returns {*}
         */
        peekSequenceNum : function () {
            return BrowserAgent.globals.sequenceNum + 1;
        },
        setDefaultMetricDefs : function () {
            return {
                NTAPI_PRT : {
                    name : "Page Render Time",
                    unit : BrowserAgent.globals.defaultMetricUnits.MILLI,
                    type : BrowserAgent.globals.metricAggregatorType.INT_LONG_DURATION
                },
                NTAPI_DPT : {
                    name : "DOM Processing Time",
                    unit : BrowserAgent.globals.defaultMetricUnits.MILLI,
                    type : BrowserAgent.globals.metricAggregatorType.INT_LONG_DURATION
                },
                NTAPI_PLT : {
                    name : "Page Load Time",
                    unit : BrowserAgent.globals.defaultMetricUnits.MILLI,
                    type : BrowserAgent.globals.metricAggregatorType.INT_LONG_DURATION
                },
                NTAPI_PST : {
                    name : "Page Stall Time",
                    unit : BrowserAgent.globals.defaultMetricUnits.MILLI,
                    type : BrowserAgent.globals.metricAggregatorType.INT_LONG_DURATION
                },
                NTAPI_PPUT : {
                    name : "Previous Page Unload Time",
                    unit : BrowserAgent.globals.defaultMetricUnits.MILLI,
                    type : BrowserAgent.globals.metricAggregatorType.INT_LONG_DURATION
                },
                NTAPI_DLT : {
                    name : "Domain Lookup Time",
                    unit : BrowserAgent.globals.defaultMetricUnits.MILLI,
                    type : BrowserAgent.globals.metricAggregatorType.INT_LONG_DURATION
                },
                NTAPI_TTFB : {
                    name : "Time to First Byte",
                    unit : BrowserAgent.globals.defaultMetricUnits.MILLI,
                    type : BrowserAgent.globals.metricAggregatorType.INT_LONG_DURATION
                },
                NTAPI_TTLB : {
                    name : "Time to Last Byte",
                    unit : BrowserAgent.globals.defaultMetricUnits.MILLI,
                    type : BrowserAgent.globals.metricAggregatorType.INT_LONG_DURATION
                },
                NTAPI_CET : {
                    name : "Connection Establishment Time",
                    unit : BrowserAgent.globals.defaultMetricUnits.MILLI,
                    type : BrowserAgent.globals.metricAggregatorType.INT_LONG_DURATION
                },
                PAGE_HPI : {
                    name : "Page Hits Per Interval",
                    unit : BrowserAgent.globals.defaultMetricUnits.NO_UNIT,
                    type : BrowserAgent.globals.metricAggregatorType.LONG_INTERVAL_COUNTER
                },
                FUNC_ET : {
                    name : "Execution Time",
                    unit : BrowserAgent.globals.defaultMetricUnits.MILLI,
                    type : BrowserAgent.globals.metricAggregatorType.INT_LONG_DURATION
                },
                FUNC_ICPI : {
                    name : "Invocation Count Per Interval",
                    unit : BrowserAgent.globals.defaultMetricUnits.NO_UNIT,
                    type : BrowserAgent.globals.metricAggregatorType.LONG_INTERVAL_COUNTER
                },
                AJAX_RLT : {
                    name : "Resource Load Time",
                    unit : BrowserAgent.globals.defaultMetricUnits.MILLI,
                    type : BrowserAgent.globals.metricAggregatorType.INT_LONG_DURATION
                },
                AJAX_TTFB : {
                    name : "Time To First Byte",
                    unit : BrowserAgent.globals.defaultMetricUnits.MILLI,
                    type : BrowserAgent.globals.metricAggregatorType.INT_LONG_DURATION
                },
                AJAX_RDT : {
                    name : "Response Download Time",
                    unit : BrowserAgent.globals.defaultMetricUnits.MILLI,
                    type : BrowserAgent.globals.metricAggregatorType.INT_LONG_DURATION
                },
                AJAX_CBET : {
                    name : "Callback Execution Time",
                    unit : BrowserAgent.globals.defaultMetricUnits.MILLI,
                    type : BrowserAgent.globals.metricAggregatorType.INT_LONG_DURATION
                },
                AJAX_ICPI : {
                    name : "Invocation Count Per Interval",
                    unit : BrowserAgent.globals.defaultMetricUnits.NO_UNIT,
                    type : BrowserAgent.globals.metricAggregatorType.LONG_INTERVAL_COUNTER
                },
                JSERR_CPI : {
                    name : "JavaScript Errors Per Interval",
                    unit : BrowserAgent.globals.defaultMetricUnits.NO_UNIT,
                    type : BrowserAgent.globals.metricAggregatorType.LONG_INTERVAL_COUNTER
                },
                PAGE_UDT : {
                    name : "User Decision Time",
                    unit : BrowserAgent.globals.defaultMetricUnits.MILLI,
                    type : BrowserAgent.globals.metricAggregatorType.INT_LONG_DURATION
                }
            };
        },
        // Only contains pages with events to process every harvest cycle
        pageWithEventsMap : {},
        // List of ids where each id references a page bucket in pageBucketsMap
        pageBucketsIdList : [],
        // Map of page buckets where key is the page id
        pageBucketsMap : {},
        pageBucketsMaxLen : 100,
        evtTypes : {
            RES : "RES",
            JSERR : "JSERR",
            FN : "FN",
            AXAEXT : "AXAEXT",
            APMEXT : "APMEXT",
            HPLOAD : "HPLOAD",
            SPLOAD : "SPLOAD",
            TTIME : "TTIME"
        },
        evtHandlers : {},
        pageBucketTypes : {
            HP : "HP",
            SP : "SP"
        },
        currPagePtr : null,
        prevPagePtr : null,
        currSession : null,
        currTTimeEvtPtr : null,
        initPageInfo : null,
        eumJSONShell : null,
        softPageLoadEvtObj : null,
        harvestIntervalId : null,
        sequenceNum : -1,
        ajaxDataKeys : {
            URL : "url",
            METHOD : "method",
            STATUS_CODE : "status",
            RESPONSE_CONTENT_LENGTH : "resSize",
            REQUEST_BODY_SIZE : "reqSize"
        },
        appInfo : null,
        // The current page Business Segment
        bs : "-1",
        // The current page Business Txn
        bt : "-1",
        // The current page Business Txn Component
        btc : "-1",
        commaChar : ",",
        // Browser Agent configs
        configs : null,
        contentLengthHdrStr : 'Content-Length',
        contentLengthHdrStrLowerCase : 'content-length',
        // this contains the cookie snapshot
        appCookies : null,
        // this contains the agent cookies
        agentCookies : null,
        //cookiePath : window.location.pathname,
        agentCookieKeys : "agentCookieKeys",
        agentCookieKeyName : {
            AGENTHOST : "AgentHost",
            SERVLETNAME : "ServletName",
            USERID : "UserId",
            AGENTPROCESS : "AgentProcess",
            AGENTNAME : "AgentName",
            WEBAPPNAME : "WebAppName"
        },
        agentCookiePrefix : "apm",
        agentCookieKeysRegexPattern : /^apm.+/,
        // Txn Correlation ID
        CorBrowsGUID : null,
        // Default BT regex that will be ignored
        defaultBTRegex : /^Default BT( via (Chrome|Edge|Firefox|IE|Safari))?$/,
        // Metric definition that consists of metric name, unit and accumulator type
        defaultMetricDefs : null,
        defaultMetricUnits : {
            NO_UNIT : null,
            MILLI : "ms"
        },
        isSoftPageLoad : true,
        // Timestamp of the last time the DOM has been updated
        domLastUpdated : null,
        // DOM observing timeout id
        domChangeTimeoutId : null,
        // DOM change polling interval id
        domChangeTimerId : null,
        // DOM Mutation Observer
        domChangeObserver : null,
        // DOM Mutation Observer config
        domChangeObserverConfig : { childList : true, characterData : true, subtree : true, attributes : true },
        // Soft page data point keys
        softPageDataKeys : {
            START : "s",
            END : "e",
            REFERRER : "r",
            URL : "url"
        },
        emptyObjStr : "{}",
        forwardSlashChar : "/",
        // Browser Agent provides capability to instrument any JS functions as long as it is in the
        // scope of the current window. The JS functions that need to be instrumented are
        // added here.
        // See BrowserAgent.funcUtils.constructInstrumentFunctionList for more details.
        functionsToInstrumentList : [],
        retryFuncIdMap : {},
        // Client server gap time in milliseconds
        gapTimeInMillis : 0,
        geoConstants : {
            "ERROR" : -255,
            "DENIED" : -401
        },
        geo : {
            lat : -401,
            lon : -401
        },
        extFuncMap : {},
        hashChar : '#',
        isStoragePresent : true,
        // Metric aggregator types are synonymous with Agent accumulator
        // types such as LONG INTERVAL COUNTER, LONG DURATION and so on
        metricAggregatorType : {
            INT_LONG_DURATION : 0,
            LONG_INTERVAL_COUNTER : 1
        },
        metricPathConsts : {
            PREFIX : "Business Segment",
            BROWSER : "Browser",
            AJAX : "AJAX Call",
            FUNC : "JavaScript Function",
            SOFTPAGE : "Soft Page",
            URL : "URL"
        },
        // Since Browser Agent instruments JS Functions within the current window's scope,
        // the original JS Functions are maintained in this map
        // See BrowserAgent.funcUtils.saveOrigObj for more details
        origFuncMap : {},
        platform : "-1",
        platformVersion : "-1",
        // Page URL with params
        pageFullURL : window.location.href,
        //pageReferrer : null,
        tTimeHandlerFlag : false,
        profileURL : "",
        resourceType : {
            AJAX : "AJAX"
        },
        snippetAttrNames : {
            SCRIPT_ID : {
                OLD : "BA_AXA",
                NEW : "ca_eum_ba"
            },
            PROFILE_URL : "data-profileUrl",
            TENANT_ID : "data-tenantID",
            APP_ID : "data-appID",
            APP_KEY : "data-appKey"
        },
        // Timestamp MACROS
        timestampNames : {
            START_TIME : "s",
            END_TIME : "e",
            CALLBACK_START_TIME : "cs",
            CALLBACK_END_TIME : "ce",
            FIRST_BYTE : "f",
            LAST_BYTE : "l",
            EXTERNAL : "ex"
        },
        pipeChar : "|",
        // Profile info that contains profileId, profileName, createdAt and lastUpdated at from app profile
        profileInfo : null,
        semiColonChar : ";",
        // The current page Txn Trace start time
        startTime : null,
        // The current page Txn trace end time
        endTime : null,
        UNDEFINED : "-1",
        userAgents : {
            CHROME : { name : "Chrome", ver : 30 },
            EDGE : { name : "Edge", ver : 12 },
            FIREFOX : { name : "Firefox", ver : 30 },
            IE : { name : "IE", ver : 11 },
            SAFARI : { name : "Safari", ver : 9 },
            UNSUPPORTED : { name : "Unsupported", ver : -1 }
        },
        browserFingerprint : null,
        baStartTime : null,
        // Data objects in this map will be inlined in every BA event
        trackerDataKey : "TKR",
        isJQOne : null,
        isJQ : null,
        retryInterval : 1000,
        funcInstrumentMaxRetryCount : 10
    };

    /**
     * BA Logger Utility for logging in browser console
     */
    BrowserAgent.logger = {
        // All Browser Agent Browser logs precede with [CA Browser Agent]:
        logPrefix : " [CA Browser Agent]: ",
        // Currently, the log levels cannot be configured from the Agent. It is merely a placeholder
        // to think about in the next release. So, the browser code is currently logging them under
        // different levels, which is not very useful at this point.
        logLevelPrefix : {
            // Most verbose logging level. Not suited for production
            DEBUG : " [DEBUG] ",
            // Used to log all unhandled exceptions, perhaps some weird scenarios
            ERROR : " [ERROR] ",
            // Used to output messages that is useful to the running and management of the system.
            INFO : " [INFO] ",
            // Used often to report handled exceptions or other important log events (e.g. missing configuration)
            WARN : " [WARN] "
        },
        /**
         * Determines if a console is present to log and BA logging is Enabled
         * @returns {boolean}
         */
        isOk : function () {
            return window.console && typeof window.console === "object" &&
                   (!BrowserAgent.globals.configs || BrowserAgent.globals.configs.BROWSERLOGGINGENABLED === true);
        },
        /**
         * Logs the given message at the given log level
         * @param logLevel
         * @param msg
         */
        log : function ( logLevel, msg ) {
            if ( BrowserAgent.logger.isOk() ) {
                window.console.log(new Date() + BrowserAgent.logger.logPrefix +
                                   logLevel + msg);
            }
        },
        debug : function ( msg ) {
            BrowserAgent.logger.log(BrowserAgent.logger.logLevelPrefix.DEBUG, msg);
        },
        error : function ( msg ) {
            BrowserAgent.logger.log(BrowserAgent.logger.logLevelPrefix.ERROR, msg);
        },
        info : function ( msg ) {
            BrowserAgent.logger.log(BrowserAgent.logger.logLevelPrefix.INFO, msg);
        },
        warn : function ( msg ) {
            BrowserAgent.logger.log(BrowserAgent.logger.logLevelPrefix.WARN, msg);
        }
    };
    /**
     * Browser Utility
     * Responsible for browser related tasks: Geo-Location
     */
    BrowserAgent.browserUtils = {
        UUIDPattern : 'xxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx',
        UUIDChar : 'x',
        XHRToSendMetrics : null,
        /**
         * Initializes browser utils
         */
        init : function () {
            // Obtain Geo-Location upon page load and store the location inside sessionStorage
            // For the remainder of the session, use the same geo-location co-ordinates
            if ( BrowserAgent.globals.configs.GEOENABLED ) {
                this.getGeoLocation();
            }
            // Generate Fingerprint
            BrowserAgent.globals.browserFingerprint = this.getBrowserFingerprint();
            // Generate Session ID
            BrowserAgent.globals.currSession = this.getSession();
        },
        /**
         * If object cannot be stringified, creates a new object with the same key/value pairs of obj
         * Otherwise, simple assignment
         * @param obj - object to be copied
         * @param isOverride - flag to override logic and create new obj copy
         * @returns {*}
         */
        copyObj : function ( obj, isOverride ) {
            if ( !obj || typeof obj !== 'object' ) {
                BrowserAgent.logger.warn("copyObj: Invalid parameters");
                return null;
            }
            var targetObj = {}, key;
            var objStr = JSON.stringify(obj);
            if ( !objStr || objStr === "{}" || isOverride ) {
                // build copy using BFS with a queue
                var queue = [];
                queue.push([null, obj, targetObj]);
                while ( queue.length > 0 ) {
                    var node = queue.shift(); // node format ["key", "value", targetObject]
                    if ( node[1] && typeof node[1] === 'object' ) {
                        //root
                        if ( !node[0] ) {
                            for ( key in node[1] ) {
                                queue.push([key, node[1][key], node[2]]);
                            }
                        }
                        //nested object
                        else {
                            node[2][node[0]] = {};
                            for ( key in node[1] ) {
                                queue.push([key, node[1][key], node[2][node[0]]]);
                            }
                        }
                    } else {
                        if ( !node[0] ) {
                            node[2] = node[1];
                        } else {
                            node[2][node[0]] = node[1];
                        }
                    }
                }
            } else {
                targetObj = obj;
            }
            return targetObj;
        },
        // Polyfill code for String.includes()
        // source:https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/includes
        includes : function ( search, start ) {
            'use strict';
            if ( typeof start !== 'number' ) {
                start = 0;
            }
            if ( start + search.length > this.length ) {
                return false;
            } else {
                return this.indexOf(search, start) !== -1;
            }
        },
        /**
         * Extracts user agent name and major version from the user agent string and checks if the user
         * agent is supported or not
         * @param userAgt
         * @returns Object
         */
        getBrowserInfo : function ( userAgt ) {
            var version = -1;
            // Sanity
            if ( !userAgt || typeof userAgt !== 'string' ) {
                return {
                    name : BrowserAgent.globals.userAgents.UNSUPPORTED.name,
                    ver : BrowserAgent.globals.userAgents.UNSUPPORTED.ver, isSupported : false
                };
            }
            // Opera
            if ( /opera|opr/i.test(userAgt) ) {
                return {
                    name : BrowserAgent.globals.userAgents.UNSUPPORTED.name,
                    ver : BrowserAgent.globals.userAgents.UNSUPPORTED.ver, isSupported : false
                };
            }
            // MS Edge
            if ( /edge/i.test(userAgt) ) {
                version = this.getMajorVersion(userAgt, /(?:edge)\/(\d+(\.\d+)?)/i);
                if ( version >= BrowserAgent.globals.userAgents.EDGE.ver ) {
                    return {
                        name : BrowserAgent.globals.userAgents.EDGE.name, ver : version, isSupported : true
                    };
                }
            }
            // IE
            if ( /msie|trident/i.test(userAgt) ) {
                version = this.getMajorVersion(userAgt, /(?:msie |rv:)(\d+(\.\d+)?)/i);
                if ( version >= BrowserAgent.globals.userAgents.IE.ver ) {
                    return {
                        name : BrowserAgent.globals.userAgents.IE.name, ver : version, isSupported : true
                    };
                }
            }
            // Chrome
            if ( /chrome|crios|crmo/i.test(userAgt) ) {
                version = this.getMajorVersion(userAgt, /(?:chrome|crios|crmo)\/(\d+(\.\d+)?)/i);
                if ( version >= BrowserAgent.globals.userAgents.CHROME.ver ) {
                    return {
                        name : BrowserAgent.globals.userAgents.CHROME.name, ver : version, isSupported : true
                    };
                }
            }
            // Firefox
            if ( /firefox|iceweasel/i.test(userAgt) ) {
                version = this.getMajorVersion(userAgt, /(?:firefox|iceweasel)[ \/](\d+(\.\d+)?)/i);
                if ( version >= BrowserAgent.globals.userAgents.FIREFOX.ver ) {
                    return {
                        name : BrowserAgent.globals.userAgents.FIREFOX.name, ver : version,
                        isSupported : true
                    };
                }
            }
            // Safari
            if ( /safari/i.test(userAgt) ) {
                version = this.getMajorVersion(userAgt, /version\/(\d+(\.\d+)?)/i);
                if ( version >= BrowserAgent.globals.userAgents.SAFARI.ver ) {
                    return {
                        name : BrowserAgent.globals.userAgents.SAFARI.name, ver : version, isSupported : true
                    };
                }
            }
            return {
                name : BrowserAgent.globals.userAgents.UNSUPPORTED.name,
                ver : BrowserAgent.globals.userAgents.UNSUPPORTED.ver, isSupported : false
            };
        },
        /**
         * Extracts the major version from the given User Agent string and regex pattern
         * @param userAgt
         * @param regExp
         * @returns Number
         */
        getMajorVersion : function ( userAgt, regExp ) {
            var matchArr = userAgt.match(regExp);
            if ( matchArr && matchArr.length > 1 ) {
                var majVer = matchArr[1].split(".");
                if ( majVer && majVer.length > 0 ) {
                    return parseInt(majVer[0]);
                }
            }
            return 0;
        },
        /**
         * Generates a 256 bit Universally Unique Identifier
         * @returns {string}
         */
        generateUUID : function () {
            var d = Date.now();
            return BrowserAgent.browserUtils.UUIDPattern.replace(/[xy]/g, function ( c ) {
                var r = (d + Math.random() * 16) % 16 | 0;
                d = Math.floor(d / 16);
                return (c == BrowserAgent.browserUtils.UUIDChar ? r : (r & 0x3 | 0x8)).toString(16);
            });
        },
        /**
         * Gets browser fingerprint. Either gets it from local storage or generates a new one and stores
         * it in local storage.
         * @returns {string}
         */
        getBrowserFingerprint : function () {
            var fing = BrowserAgent.storageUtils.getFromStorage(BrowserAgent.storageUtils.storageTypes.LOCAL,
                                                                BrowserAgent.storageUtils.storageKeys.BAFINGERPRINT);
            if ( fing ) {
                BrowserAgent.logger.info("getBrowserFingerprint: Browser Fingerprint already exists.");
                return fing;
            }
            BrowserAgent.logger.info("getBrowserFingerprint: Generating a new Browser Fingerprint...");
            fing = BrowserAgent.browserUtils.generateUUID();
            BrowserAgent.storageUtils.putInStorage(BrowserAgent.storageUtils.storageTypes.LOCAL,
                                                   BrowserAgent.storageUtils.storageKeys.BAFINGERPRINT,
                                                   fing, false);
            return fing;
        },
        /**
         * Gets page session which contains session id, session start time and isNewSession flag.
         * Only session id and session start time will be stored in session storage.
         * @returns {*}
         */
        getSession : function () {
            var ssID = BrowserAgent.storageUtils.getFromStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                                BrowserAgent.storageUtils.storageKeys.BASESSION_ID);
            var ssStart;
            if ( ssID ) {
                BrowserAgent.logger.info("getSession: Browser Session ID already exists.");
                if ( !BrowserAgent.browserUtils.isSameSession(BrowserAgent.globals.baStartTime) ) {
                    return BrowserAgent.browserUtils.getNewSession(BrowserAgent.globals.baStartTime);
                }
                var sessionInfo = {};
                sessionInfo.id = ssID;
                sessionInfo.isNewSession = false;
                ssStart =
                    BrowserAgent.browserUtils.convertToNum(BrowserAgent.storageUtils.getFromStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                                                                    BrowserAgent.storageUtils.storageKeys.BASESSION_STARTTIME));
                if ( ssStart !== null ) {
                    sessionInfo.startTime = ssStart;
                }
                return sessionInfo;
            }
            return BrowserAgent.browserUtils.getNewSession(BrowserAgent.globals.baStartTime);
        },
        /**
         * Creates a new BA session and stores the new session information in browser's sessionStorage
         * @param currentEventTime
         * @returns {{id: (*|string), startTime: *, isNewSession: boolean}}
         */
        getNewSession : function ( currentEventTime ) {
            BrowserAgent.logger.info("getNewSession: Generating a new Session ID...");
            var ssID = BrowserAgent.browserUtils.generateUUID();
            BrowserAgent.browserUtils.updateSessionInfo(ssID, currentEventTime, true);
            // AXA txns do not span across sessions. So, clear tracker data upon new session creation
            if ( typeof BrowserAgentExtension !== 'undefined' ) {
                BrowserAgentExtension.internal.clearAllTrackers();
            }
            return {
                id : ssID,
                startTime : currentEventTime,
                isNewSession : true
            };
        },
        /**
         * Updates the session information in browser's sessionStorage
         * @param ssID
         * @param ssStart
         * @param isIdempotent
         */
        updateSessionInfo : function ( ssID, ssStart, isIdempotent ) {
            BrowserAgent.storageUtils.putInStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                   BrowserAgent.storageUtils.storageKeys.BASESSION_ID,
                                                   ssID, isIdempotent);
            BrowserAgent.storageUtils.putInStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                   BrowserAgent.storageUtils.storageKeys.BASESSION_STARTTIME,
                                                   ssStart, isIdempotent);
            BrowserAgent.storageUtils.putInStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                   BrowserAgent.storageUtils.storageKeys.BALASTEVENT_TIME,
                                                   ssStart, isIdempotent);
        },
        /**
         * Determines if the current session is timed out due to inactivity or not
         * @param currEventTime
         * @returns {boolean}
         */
        isSameSession : function ( currEventTime ) {
            if ( typeof currEventTime !== 'number' || isNaN(currEventTime) ) {
                BrowserAgent.logger.error("isSameSession: Cannot determine session truth as event time is NaN.");
                return true;
            }
            var lastEventTime = BrowserAgent.browserUtils.convertToNum(BrowserAgent.storageUtils.getFromStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                                                                                BrowserAgent.storageUtils.storageKeys.BALASTEVENT_TIME));
            if ( lastEventTime !== null &&
                 (currEventTime - lastEventTime) >= BrowserAgent.globals.configs.SESSIONTIMEOUT ) {
                BrowserAgent.logger.info("isSameSession: Session timed out due to inactivity.");
                return false;
            }
            return true;
        },
        /**
         * Returns true if a custom geolocation was found or not.
         */
        hasCustomGeoLocation : function () {
            var customLocationStr =
                BrowserAgent.storageUtils.getFromStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                         BrowserAgent.storageUtils.storageKeys.GEOCUSTOM);

            return customLocationStr !== null;
        },
        /**
         * Obtain Latitude and Longitude with HTML5 Geo-Location API
         * Note: The Latitude and Longitude will be returned by the Callbacks
         */
        getGeoLocation : function () {
            // if using a custom location, ignore browser location and return
            if ( BrowserAgent.browserUtils.hasCustomGeoLocation() ) {
                return;
            }

            if ( !navigator || !navigator.geolocation ) {
                BrowserAgent.logger.warn("getGeoLocation: Geolocation is not supported in this browser.");
                BrowserAgent.storageUtils.putInStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                       BrowserAgent.storageUtils.storageKeys.GEOLAT,
                                                       BrowserAgent.globals.geoConstants.ERROR, true);
                BrowserAgent.storageUtils.putInStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                       BrowserAgent.storageUtils.storageKeys.GEOLONG,
                                                       BrowserAgent.globals.geoConstants.ERROR, true);
                return;
            }
            var lat = BrowserAgent.storageUtils.getFromStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                               BrowserAgent.storageUtils.storageKeys.GEOLAT);
            var lon = BrowserAgent.storageUtils.getFromStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                               BrowserAgent.storageUtils.storageKeys.GEOLONG);
            // Compute Geo-location only if BrowserAgentLat or BrowserAgentLong are not present in
            // sessionStorage
            if ( lat === null || lon === null ) {
                var options = {
                    timeout : BrowserAgent.globals.configs.GEOTIMEOUT,
                    maximumAge : BrowserAgent.globals.configs.GEOMAXIMUMAGE,
                    enableHighAccuracy : BrowserAgent.globals.configs.GEOHIGHACCURACYENABLED
                };
                BrowserAgent.logger.info("getGeoLocation: Attempting to calculate geo location");
                navigator.geolocation.getCurrentPosition(this.geoLocationFound,
                                                         this.geoLocationNotFound, options);
                // In some browsers, the error callback is never called upon cancellation of the
                // location popup (e.g. clicking the X button) and in some browsers, the timeout
                // option is non-functional. So, do it ourselves.
                // After timeout and some grace time period, set the sessionStorage geo location to
                // the same values as those of user denial
                setTimeout(function () {
                    if ( BrowserAgent.storageUtils.getFromStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                                  BrowserAgent.storageUtils.storageKeys.GEOLAT) ===
                         null ) {
                        BrowserAgent.logger.warn("getGeoLocation: Never received a response for geo-location. Setting co-ordinates to " +
                                                 BrowserAgent.globals.geoConstants.DENIED + "," +
                                                 BrowserAgent.globals.geoConstants.DENIED);
                        // If the user did not respond to the pop-up or just clicked on X button of the pop-up,
                        // then we assume that user does not want to reveal location. So, set a special code to
                        // indicate this choice. Why 401? HTTP 401 is "Unauthorized Access"
                        BrowserAgent.globals.geo.lat = BrowserAgent.globals.geoConstants.DENIED;
                        BrowserAgent.globals.geo.lon = BrowserAgent.globals.geoConstants.DENIED;
                        BrowserAgent.storageUtils.putInStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                               BrowserAgent.storageUtils.storageKeys.GEOLAT,
                                                               BrowserAgent.globals.geoConstants.DENIED,
                                                               true);
                        BrowserAgent.storageUtils.putInStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                               BrowserAgent.storageUtils.storageKeys.GEOLONG,
                                                               BrowserAgent.globals.geoConstants.DENIED,
                                                               true);
                    }
                }, parseInt(BrowserAgent.globals.configs.GEOTIMEOUT) + 5000);
            } else {
                BrowserAgent.globals.geo.lat = Number(lat);
                BrowserAgent.globals.geo.lon = Number(lon);
            }
        },
        /**
         * Success Callback for getGeoLocation
         * @param position - HTML5 position object
         */
        geoLocationFound : function ( position ) {
            // Should never get here since call back was never registered. Just in case..
            // if using a custom location, ignore browser location and return
            if ( BrowserAgent.browserUtils.hasCustomGeoLocation() ) {
                return;
            }

            BrowserAgent.globals.geo.lat = position.coords.latitude;
            BrowserAgent.globals.geo.lon = position.coords.longitude;
            BrowserAgent.storageUtils.putInStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                   BrowserAgent.storageUtils.storageKeys.GEOLAT,
                                                   BrowserAgent.globals.geo.lat, true);
            BrowserAgent.storageUtils.putInStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                   BrowserAgent.storageUtils.storageKeys.GEOLONG,
                                                   BrowserAgent.globals.geo.lon, true);
        },
        /**
         * Error Callback for getGeoLocation
         * @param error - error code from the HTML5 geolocation API
         */
        geoLocationNotFound : function ( error ) {
            // Should never get here since call back was never registered. Just in case..
            // if using a custom location, ignore browser location and return
            if ( BrowserAgent.browserUtils.hasCustomGeoLocation() ) {
                return;
            }

            var isDenied = false;
            switch ( error.code ) {
                case error.PERMISSION_DENIED:
                    BrowserAgent.logger.warn("geoLocationNotFound: Browser indicates that user denied the request for geo-location.");
                    isDenied = true;
                    break;
                case error.POSITION_UNAVAILABLE:
                    BrowserAgent.logger.warn("geoLocationNotFound: Browser's geo-location information is unavailable.");
                    break;
                case error.TIMEOUT:
                    BrowserAgent.logger.warn("geoLocationNotFound: Browser's request to obtain geo-location timed out.");
                    break;
                default:
                    BrowserAgent.logger.warn("geoLocationNotFound: An unknown error occurred while browser attempted geo-location.");
                    break;
            }
            // If the user denies to reveal location, then set a special code to indicate this choice. Why 401?
            // HTTP 401 is "Unauthorized Access"
            if ( isDenied ) {
                BrowserAgent.globals.geo.lat = BrowserAgent.globals.geoConstants.DENIED;
                BrowserAgent.globals.geo.lon = BrowserAgent.globals.geoConstants.DENIED;
            } else {
                BrowserAgent.globals.geo.lat = BrowserAgent.globals.geoConstants.ERROR;
                BrowserAgent.globals.geo.lon = BrowserAgent.globals.geoConstants.ERROR;
            }
            BrowserAgent.storageUtils.putInStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                   BrowserAgent.storageUtils.storageKeys.GEOLAT,
                                                   BrowserAgent.globals.geo.lat, true);
            BrowserAgent.storageUtils.putInStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                   BrowserAgent.storageUtils.storageKeys.GEOLONG,
                                                   BrowserAgent.globals.geo.lon, true);
        },
        /**
         * Converts the input to a number.
         * @param data
         * @returns a number or null if it cannot be converted to a number
         */
        convertToNum : function ( data ) {
            // Number(null) -> 0, Number(undefined) -> NaN, Number(string) -> NaN
            if ( BrowserAgent.browserUtils.getObjType(data) === 'Number' || data === null ) {
                return data;
            }
            var num = Number(data);
            return isNaN(num) ? null : num;
        },
        /**
         * Gets the type of an object in Proper Case (first letter capitalized) including custom objects.
         * Some special cases: null -> 'Null', undefined -> 'Undefined'
         * @param obj
         * @returns string - type of object with Proper Case
         */
        getObjType : function ( obj ) {
            var type = typeof obj;
            if ( typeof obj !== 'object' ) {
                // All primitive types
                // Capitalize first character to be consistent with all other cases below
                return type.charAt(0).toUpperCase() + type.slice(1);
            }
            try {
                // Object.prototype.toString.call(obj) returns, e.g. "[object Number]"
                type = Object.prototype.toString.call(obj).slice(8, -1);
                if ( typeof type !== 'string' || type === "" ) {
                    return 'Object';
                }
            } catch ( e ) {
                BrowserAgent.logger.error("getObjType: " + e.message);
                type = null;
            }
            return type;
        },
        /**
         * Clone the given tracker data object and return a list
         * Note: DO NOT USE if the object to be cloned stores functions inside it
         * @returns {Array}
         */
        cloneTrackerData : function () {
            var temp, trackerDataList = [], trkrData = JSON.parse(BrowserAgent.storageUtils.getFromStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                                                                           BrowserAgent.storageUtils.storageKeys.BATRKR));
            if ( !trkrData ) {
                return trackerDataList;
            }
            for ( var item in trkrData ) {
                temp = JSON.stringify(trkrData[item]);
                if ( temp === BrowserAgent.globals.emptyObjStr ) {
                    continue;
                }
                trackerDataList.push(trkrData[item]);
            }
            return trackerDataList;
        },
        /**
         * Redefine the XHR object's open and send call to original
         * Dispatch of BrowserAgent metrics requires XHR object. However, BrowserAgent instrumentation
         * add custom logic into the methods of this object. Hence, redefine them to
         * the original for the sake of metrics dispatch
         */
        getXHRforBAMetrics : function () {
            if ( BrowserAgent.globals.origFuncMap && BrowserAgent.globals.origFuncMap.XHR_ctor &&
                 BrowserAgent.globals.origFuncMap.XHR_ctor_open &&
                 BrowserAgent.globals.origFuncMap.XHR_ctor_send ) {
                BrowserAgent.browserUtils.XHRToSendMetrics =
                    new (BrowserAgent.globals.origFuncMap.XHR_ctor)();
                BrowserAgent.browserUtils.XHRToSendMetrics.open =
                    BrowserAgent.globals.origFuncMap.XHR_ctor_open;
                BrowserAgent.browserUtils.XHRToSendMetrics.send =
                    BrowserAgent.globals.origFuncMap.XHR_ctor_send;
            } else {
                BrowserAgent.browserUtils.XHRToSendMetrics = new XMLHttpRequest();
            }
        },
        /**
         * Replaces all occurrences of a character or a string inside a string with another.
         * Note: Need to escape special characters in "find" before passing in!
         * @param str - original string
         * @param find - string to be replaced
         * @param replace - string to replace
         * @returns {*}
         */
        replaceAll : function ( str, find, replace ) {
            if ( typeof str !== 'string' || typeof find !== 'string' || typeof replace !== 'string' ) {
                BrowserAgent.logger.error("replaceAll: Invalid input");
                return null;
            }
            return str.replace(new RegExp(find, 'g'), replace);
        },
        /**
         * Parses URL and returns pieces of it.
         * 1. Remove query params
         * 2. Remove chars after semi-colons
         * 3. Remove protocol (http, https)
         * 4. Append Port # if not present
         * 5. Decode hostname, pathname and hash value
         * @param url - HTTP URL, relative or absolute
         * @returns {*}
         */
        parseURL : function ( url ) {
            if ( typeof url !== 'string' || url.length < 1 ) {
                BrowserAgent.logger.warn("parseURL : Not a valid URL. Skipping parse...");
                return null;
            }
            // Note: there is no need to remove the element as the element is removed
            // outside the scope of this method as it has no parent
            var parser = document.createElement('a');
            parser.href = url;
            // Get port number
            var port = parser.port;
            if ( port.length === 0 ) {
                // Get default port number based on protocol
                port = 80;
                if ( parser.protocol.indexOf("https") === 0 ) {
                    port = 443;
                }
            }
            return {
                hostname : decodeURIComponent(parser.hostname),
                port : port,
                pathname : decodeURIComponent(parser.pathname),
                hash : decodeURIComponent(parser.hash),
                href : parser.href
            };
        },
        /**
         * Decodes and trims the full URL:
         * 1. Strip Query Params
         * 2. Remove chars after semi-colons
         * @param urlStr - HTTP URL
         * @returns {*}
         */
        trimURL : function ( urlStr ) {
            if ( typeof urlStr !== 'string' ) {
                BrowserAgent.logger.error("trimURL: Invalid URL - " + urlStr);
                return null;
            }
            // Remove Query Parameters, if any
            var queryIdx = urlStr.indexOf('?');
            if ( queryIdx !== -1 ) {
                urlStr = urlStr.substring(0, queryIdx);
            }
            // Remove things after Semi-colons
            // e.g. URL/path;jsessionid=39y459hnfannfla
            var semiColonIdx = urlStr.indexOf(BrowserAgent.globals.semiColonChar);
            if ( urlStr && semiColonIdx !== -1 ) {
                urlStr = urlStr.substring(0, semiColonIdx);
            }
            return urlStr;
        },
        /**
         * Get the full url of a given url including protocol, host, port, pathname and query parameters
         * @param url - url string that can be a relative path or a full url
         * @returns full url including protocol, host, port, pathname and query parameters
         */
        getFullURL : function ( url ) {
            if ( typeof url !== 'string' || url.length < 1 ) {
                BrowserAgent.logger.warn("getFullURL : Not a valid URL. Skipping parse...");
                return null;
            }
            // Note: there is no need to remove the element as the element is removed
            // outside the scope of this method as it has no parent
            var parser = document.createElement('a');
            // Let the browser do the work
            parser.href = url;
            return parser.href;
        },
        /**
         * Determines if jQuery and jQuery 1.x is present in the current window scope
         */
        isJQPresent : function () {
            if ( typeof jQuery !== 'undefined' ) {
                BrowserAgent.globals.isJQ = true;
                // Is jQuery 1.x present?
                if ( jQuery.fn.jquery.match(/^1\.\d+.*/) !== null ) {
                    BrowserAgent.globals.isJQOne = true;
                    BrowserAgent.logger.info("isJQOnePresent: jQuery 1.x detected.");
                } else {
                    BrowserAgent.globals.isJQOne = false;
                }
            } else {
                BrowserAgent.globals.isJQ = false;
                BrowserAgent.globals.isJQOne = false;
            }
        }
    };
    /**
     * Config Utility
     * Responsible for Server to Browser Configuration
     */
    BrowserAgent.configUtils = {
        /**
         * Known configuration parameters
         */
        configNames : {
            // Don't move this down because log messages are printed in the case of browser logging is disabled.
            // Toggles Browser Logging
            BROWSERLOGGINGENABLED : "browserLoggingEnabled",
            // Toggles AJAX metrics
            AJAXMETRICSENABLED : "ajaxMetricsEnabled",
            // Threshold to filter AJAX metrics
            // Note: AJAX calls whose Resource Load Time < threshold are ignored
            AJAXMETRICSTHRESHOLD : "ajaxMetricsThreshold",
            // Toggles BA feature
            BROWSERAGENTENABLED : "browserAgentEnabled",
            // URL to which the metrics are to be dispatched
            COLLECTORURL : "collectorUrl",
            // Toggles Geo-Location
            GEOENABLED : "geoEnabled",
            // Toggles Geo-Location High Accuracy Mode
            GEOHIGHACCURACYENABLED : "geoHighAccuracyEnabled",
            // Specifies the interval for which the previous Geo-Location values are to be used
            GEOMAXIMUMAGE : "geoMaximumAge",
            // Specifies the interval to wait for the current Geo-Location calculation
            GEOTIMEOUT : "geoTimeout",
            // Toggles JS Error feature
            JSERRORSENABLED : 'jsErrorsEnabled',
            // Toggles JS function metrics
            JSFUNCTIONMETRICSENABLED : "jsFunctionMetricsEnabled",
            // Threshold to filter JS function metrics
            // Note: JS functions whose execution time < threshold are ignored
            JSFUNCTIONMETRICSTHRESHOLD : "jsFunctionMetricsThreshold",
            // The frequency at which BA metrics are dispatched from the browser
            METRICFREQUENCY : "metricFrequency",
            // Toggles page load metrics
            PAGELOADMETRICSENABLED : "pageLoadMetricsEnabled",
            // Threshold to filter page load metrics
            // Note: Pages whose page load complete time < threshold are ignored
            PAGELOADMETRICSTHRESHOLD : "pageLoadMetricsThreshold",
            // Specifies the inactive interval in which a new session is created
            SESSIONTIMEOUT : "sessionTimeout",
            // List of URLs for which the BA monitoring is to be ignored
            // JS regex matching on full URLs
            URLEXCLUDELIST : "urlExcludeList",
            // List of URLs that BA should monitor
            // JS regex matching on full URLs
            URLINCLUDELIST : "urlIncludeList",
            // Toggles URL metric context (no BT) for APM
            URLMETRICOFF : "urlMetricOff",
            // DOM change observer timeout if cannot detect end of DOM load or user interaction
            DOMCHANGETIMEOUT : "domChangeTimeout",
            // DOM change polling interval
            DOMCHANGEINTERVAL : "domChangePollingInterval",
            // Toggle Application cookies capture
            COOKIECAPTUREENABLED : "cookieCaptureEnabled"
        },
        /**
         * Default values for the known configuration parameters
         */
        defaults : {
            BROWSERLOGGINGENABLED : false,
            AJAXMETRICSENABLED : true,
            AJAXMETRICSTHRESHOLD : 100,
            BROWSERAGENTENABLED : false,
            COLLECTORURL : "",
            GEOENABLED : false,
            GEOHIGHACCURACYENABLED : false,
            GEOMAXIMUMAGE : 10000,
            GEOTIMEOUT : 5000,
            JSERRORSENABLED : true,
            JSFUNCTIONMETRICSENABLED : false,
            JSFUNCTIONMETRICSTHRESHOLD : 100,
            METRICFREQUENCY : 3750,
            PAGELOADMETRICSENABLED : true,
            PAGELOADMETRICSTHRESHOLD : 100,
            SESSIONTIMEOUT : 3600000,
            URLEXCLUDELIST : [],
            URLINCLUDELIST : [],
            URLMETRICOFF : false,
            DOMCHANGETIMEOUT : 10000,
            DOMCHANGEINTERVAL : 100,
            COOKIECAPTUREENABLED : false
        },
        /**
         * Validates each BrowserAgent configuration in the app profile and extracts profile info.
         * If configuration is invalid, use default value.
         * @param appProfile
         * @returns {boolean} - true if successfully processed app profile
         */
        processAppProfile : function ( appProfile ) {
            if ( !appProfile || !appProfile.baAttributes ) {
                BrowserAgent.logger.error("processAppProfile: Invalid app profile.");
                return false;
            }
            var oorMsg = " is out of range. Defaulting to ";
            for ( var configName in BrowserAgent.configUtils.configNames ) {
                var configVal = appProfile.baAttributes[BrowserAgent.configUtils.configNames[configName]];
                var defaultVal = BrowserAgent.configUtils.defaults[configName];
                var type = BrowserAgent.browserUtils.getObjType(configVal);
                if ( type === BrowserAgent.browserUtils.getObjType(defaultVal) ) {
                    if ( type !== 'Number' || configVal >= 0 ) {
                        BrowserAgent.globals.configs[configName] = configVal.valueOf();
                        continue;
                    }
                }
                BrowserAgent.logger.info("processAppProfile: " + BrowserAgent.configUtils.configNames[configName] +
                                         " is not provided or invalid. Defaulting to " + JSON.stringify(defaultVal));
                BrowserAgent.globals.configs[configName] = defaultVal;
            }
            if ( BrowserAgent.globals.configs.METRICFREQUENCY > 7500 ) {
                BrowserAgent.logger.warn("processAppProfile: " + BrowserAgent.configUtils.configNames.METRICFREQUENCY +
                                         oorMsg + BrowserAgent.configUtils.defaults.METRICFREQUENCY);
                BrowserAgent.globals.configs.METRICFREQUENCY = BrowserAgent.configUtils.defaults.METRICFREQUENCY;
            }
            if ( BrowserAgent.globals.configs.DOMCHANGEINTERVAL < 50 ||
                 BrowserAgent.globals.configs.DOMCHANGEINTERVAL > 1000 ) {
                BrowserAgent.logger.warn("processAppProfile: " +
                                         BrowserAgent.configUtils.configNames.DOMCHANGEINTERVAL + oorMsg +
                                         BrowserAgent.configUtils.defaults.DOMCHANGEINTERVAL);
                BrowserAgent.globals.configs.DOMCHANGEINTERVAL = BrowserAgent.configUtils.defaults.DOMCHANGEINTERVAL;
            }
            if ( BrowserAgent.globals.configs.DOMCHANGETIMEOUT < 200 ||
                 BrowserAgent.globals.configs.DOMCHANGETIMEOUT > 15000 ) {
                BrowserAgent.logger.warn("processAppProfile: " +
                                         BrowserAgent.configUtils.configNames.DOMCHANGETIMEOUT + oorMsg +
                                         BrowserAgent.configUtils.defaults.DOMCHANGETIMEOUT);
                BrowserAgent.globals.configs.DOMCHANGETIMEOUT = BrowserAgent.configUtils.defaults.DOMCHANGETIMEOUT;
            }
            if ( BrowserAgent.globals.configs.DOMCHANGETIMEOUT <= BrowserAgent.globals.configs.DOMCHANGEINTERVAL ) {
                BrowserAgent.logger.warn("processAppProfile: " + BrowserAgent.configUtils.configNames.DOMCHANGETIMEOUT +
                                         " cannot be less than or equal to " +
                                         BrowserAgent.configUtils.configNames.DOMCHANGEINTERVAL +
                                         ". Using default values.");
                BrowserAgent.globals.configs.DOMCHANGEINTERVAL = BrowserAgent.configUtils.defaults.DOMCHANGEINTERVAL;
                BrowserAgent.globals.configs.DOMCHANGETIMEOUT = BrowserAgent.configUtils.defaults.DOMCHANGETIMEOUT;
            }
            BrowserAgent.globals.profileInfo = BrowserAgent.configUtils.extractProfileInfo(appProfile);
            return true;
        },
        /**
         * Makes an AJAX call to get new app profile from specified profileURL. Updates configurations
         * and turn on/off features as appropriate.
         * @param profileURL
         */
        getAppProfile : function ( profileURL ) {
            BrowserAgent.browserUtils.getXHRforBAMetrics();
            var xhr = BrowserAgent.browserUtils.XHRToSendMetrics;
            if ( xhr ) {
                xhr.open('GET', profileURL, true);
                xhr.onreadystatechange = function () {
                    if ( this.readyState === this.DONE && this.status === 200 ) {
                        var appProfile = null;
                        try { // JSON.parse() will throw error if input is invalid
                            appProfile = JSON.parse(xhr.responseText);
                        } catch ( e ) {
                            BrowserAgent.logger.error("getAppProfile: Invalid app profile - " + e.message +
                                                      ". Disabling Browser Agent...");
                            BrowserAgent.configUtils.disableBA();
                            return;
                        }
                        BrowserAgent.logger.info("getAppProfile: Successfully obtained new app profile.");
                        BrowserAgent.configUtils.updateAppProfile(appProfile);
                    }
                };
                xhr.send();
            }
        },
        /**
         * Extracts profileUrl, tenantId, appId and appKey from script tag and put them in
         * BrowserAgent.globals.
         * @returns {boolean} - true if extraction is successful
         */
        extractAppInfo : function () {
            // Use CSS selectors to search for the first element with logical OR of old and new script ids
            // A logical OR is achieved via comma, AND via dot and NOT via not()
            var cssSelector = BrowserAgent.globals.hashChar +
                              BrowserAgent.globals.snippetAttrNames.SCRIPT_ID.NEW + BrowserAgent.globals.commaChar +
                              BrowserAgent.globals.hashChar + BrowserAgent.globals.snippetAttrNames.SCRIPT_ID.OLD;
            // Why not querySelectorAll?
            // 1. The multiple snippet case is already taken care of at the top of this file
            // 2. It is highly unlikely that another element will match on our script ids
            // 3. We would be the first script in most cases, so why search the whole DOM for all instances
            var elem = document.querySelector(cssSelector);
            if ( !elem ) {
                // If the snippet doesn't exist, then do nothing
                // This could happen in cases of document.write where the DOM is destroyed,
                // but script could be present in the background
                BrowserAgent.logger.error("extractAppInfo: Snippet is not found. App information could not be extracted.");
                return false;
            }
            var profileURL = elem.getAttribute(BrowserAgent.globals.snippetAttrNames.PROFILE_URL);
            if ( typeof profileURL !== 'string' || profileURL === "" ) {
                BrowserAgent.logger.error("extractAppInfo: Unable to obtain profile URL.");
                return false;
            }
            BrowserAgent.globals.profileURL = profileURL;
            var appID = elem.getAttribute(BrowserAgent.globals.snippetAttrNames.APP_ID);
            var appKey = elem.getAttribute(BrowserAgent.globals.snippetAttrNames.APP_KEY);
            var tenantID = elem.getAttribute(BrowserAgent.globals.snippetAttrNames.TENANT_ID);
            if ( typeof appID !== 'string' || appID === "" || typeof appKey !== 'string' || appKey === "" ||
                 typeof tenantID !== 'string' || tenantID === "" ) {
                BrowserAgent.logger.error("extractAppInfo: Unable to obtain App specific information.");
                return false;
            }
            BrowserAgent.globals.appInfo = {
                id : appID,
                key : appKey,
                tenantId : tenantID
            };
            return true;
        },
        /**
         * Updates current configurations with new configurations from app profile and turns on/off
         * features as appropriate.
         * @param appProfile
         */
        updateAppProfile : function ( appProfile ) {
            var origMetricFreq = BrowserAgent.globals.configs.METRICFREQUENCY;
            var origIsJSErrEnabled = BrowserAgent.globals.configs.JSERRORSENABLED;
            var origPageEnabled = BrowserAgent.globals.configs.PAGELOADMETRICSENABLED;
            if ( !BrowserAgent.configUtils.processAppProfile(appProfile) ) {
                BrowserAgent.logger.info("updateAppProfile: Using existing app profile.");
                return;
            }
            // Check if BA is enabled. It can only be changed from true to false.
            if ( BrowserAgent.globals.configs.BROWSERAGENTENABLED === false ) {
                BrowserAgent.logger.info("updateAppProfile: Browser Agent is DISABLED.");
                BrowserAgent.configUtils.disableBA();
                return;
            }
            // Check collector url
            if ( typeof BrowserAgent.globals.configs.COLLECTORURL !== 'string' ||
                 BrowserAgent.globals.configs.COLLECTORURL === "" ) {
                BrowserAgent.logger.warn("updateAppProfile: Invalid collector url. Disabling Browser Agent...");
                BrowserAgent.configUtils.disableBA();
                return;
            }
            // Check if current page is excluded
            var isExcludedNew = BrowserAgent.configUtils.isUrlExcluded(window.location.href);
            if ( BrowserAgent.globals.currPagePtr.isExcluded !== isExcludedNew && isExcludedNew === true ) {
                BrowserAgent.logger.info("updateAppProfile: Page [" + window.location.href +
                                         "] is configured to be EXCLUDED. Skipping all instrumentation on this page...");
            }
            BrowserAgent.globals.currPagePtr.isExcluded = isExcludedNew;

            // Soft page feature
            if ( origPageEnabled !== BrowserAgent.globals.configs.PAGELOADMETRICSENABLED ) {
                if ( BrowserAgent.globals.configs.PAGELOADMETRICSENABLED === true ) {
                    if ( window.MutationObserver && window.history ) {
                        BrowserAgent.globals.isSoftPageLoad = true;
                    }
                } else {
                    BrowserAgent.pageUtils.disableSoftPages();
                }
            }
            // Check if JS Error metrics are enabled
            if ( origIsJSErrEnabled !== BrowserAgent.globals.configs.JSERRORSENABLED ) {
                if ( BrowserAgent.globals.configs.JSERRORSENABLED === false ) {
                    BrowserAgent.logger.info("updateAppProfile: JS Error Monitoring is DISABLED. Detaching from window.onerror event...");
                    window.removeEventListener("error", BrowserAgent.errorUtils.captureJSError);
                    //BrowserAgent.globals.metricTypeToAccumulatorMap[BrowserAgent.globals.metricType.ERROR] = {};
                } else { // Disable -> Enabled. So, start the capture
                    BrowserAgent.errorUtils.init();
                }
            }
            // Check if geolocation is enabled
            if ( BrowserAgent.globals.configs.GEOENABLED === true ) {
                BrowserAgent.browserUtils.getGeoLocation();
            } else {
                BrowserAgent.globals.geo.lat = BrowserAgent.globals.geoConstants.ERROR;
                BrowserAgent.globals.geo.lon = BrowserAgent.globals.geoConstants.ERROR;
                delete BrowserAgent.globals.eumJSONShell.clientInfo.geolocation;
            }
            // Check metric frequency
            if ( origMetricFreq !== BrowserAgent.globals.configs.METRICFREQUENCY ) {
                if ( BrowserAgent.globals.harvestIntervalId ) {
                    clearInterval(BrowserAgent.globals.harvestIntervalId);
                    BrowserAgent.globals.harvestIntervalId = setInterval(BrowserAgent.evtUtils.harvestEvts,
                                                                         BrowserAgent.globals.configs.METRICFREQUENCY);
                }
            }
        },
        /**
         * Extracts profileId, profileName, created and lastUpdated from app profile.
         * @param appProfile
         * @returns {*}
         */
        extractProfileInfo : function ( appProfile ) {
            if ( !appProfile ) {
                return null;
            }
            var profileInfo = {};
            var isValid = false;
            if ( appProfile.profileId ) {
                profileInfo.id = appProfile.profileId;
                isValid = true;
            }
            if ( appProfile.profileName ) {
                profileInfo.name = appProfile.profileName;
                isValid = true;
            }
            if ( appProfile.created ) {
                profileInfo.createdAt = appProfile.created;
                isValid = true;
            }
            if ( appProfile.lastUpdated ) {
                profileInfo.lastUpdatedAt = appProfile.lastUpdated;
                isValid = true;
            }
            return (isValid) ? profileInfo : null;
        },
        /**
         * Disables Browser Agent.
         */
        disableBA : function () {
            // Clear the harvest interval
            if ( BrowserAgent.globals.harvestIntervalId ) {
                clearInterval(BrowserAgent.globals.harvestIntervalId);
                BrowserAgent.globals.harvestIntervalId = null;
            }
            // Drop all page buckets
            BrowserAgent.globals.pageWithEventsMap = {};
            BrowserAgent.globals.pageBucketsMap = {};
            BrowserAgent.globals.pageBucketsIdList = [];
            BrowserAgent.globals.currTTimeEvtPtr = null;
            BrowserAgent.globals.currPagePtr = null;
            // Clear all the retry set timeouts
            for ( var item in BrowserAgent.globals.retryFuncIdMap ) {
                clearTimeout(BrowserAgent.globals.retryFuncIdMap[item]);
            }
            // Remove event handlers
            window.removeEventListener("error", BrowserAgent.errorUtils.captureJSError);
            window.removeEventListener("beforeunload", BrowserAgent.pageUtils.tTimeHandler, true);
            window.removeEventListener("pagehide", BrowserAgent.pageUtils.tTimeHandler, true);

            // Disable soft page instrumentation
            BrowserAgent.pageUtils.disableSoftPages();
            BrowserAgent.globals.configs.BROWSERAGENTENABLED = false;
            BrowserAgent.globals.configs.JSERRORSENABLED = false;
            BrowserAgent.globals.configs.PAGELOADMETRICSENABLED = false;
            BrowserAgent.globals.configs.AJAXMETRICSENABLED = false;
            BrowserAgent.globals.configs.JSFUNCTIONMETRICSENABLED = false;
            BrowserAgent.globals.configs.GEOENABLED = false;
            // Don't move this up because all log messages up to this point should be displayed to the user
            BrowserAgent.globals.configs.BROWSERLOGGINGENABLED = false;
        },
        /**
         * Determines if the given full URL is to be ignored for BrowserAgent by comparing to the
         * ExcludeURLList and IncludeURLList
         * @param url - url path with no trailing slashes
         * @returns boolean : true if the given URL is to be excluded; false otherwise
         */
        isUrlExcluded : function ( url ) {
            if ( typeof url !== 'string' || url.length < 1 ) {
                BrowserAgent.logger.warn("isUrlExcluded: Invalid URL. Skipping URL exclusion check...");
                return false;
            }
            var includeUrlList = BrowserAgent.globals.configs.URLINCLUDELIST;
            var excludeUrlList = BrowserAgent.globals.configs.URLEXCLUDELIST;
            return ( (excludeUrlList.length > 0 &&
                      BrowserAgent.configUtils.isUrlInRegexList(url, excludeUrlList)) ||
                     (includeUrlList.length > 0 && !BrowserAgent.configUtils.isUrlInRegexList(url, includeUrlList)) );
        },
        /**
         * Determines if an url matches a pattern in the regex list
         * @param url - to be tested
         * @param list - regex list
         * @returns {boolean}
         */
        isUrlInRegexList : function ( url, list ) {
            for ( var i = 0; i < list.length; i++ ) {
                if ( (new RegExp(list[i])).test(url) ) {
                    return true;
                }
            }
            return false;
        }
    };
    /**
     * Storage Utility
     * Responsible for managing browser localStorage and sessionStorage
     */
    BrowserAgent.storageUtils = {
        storageTypes : {
            SESSION : 0,
            LOCAL : 1
        },
        storageKeys : {
            GEOLAT : "BALat",
            GEOLONG : "BALong",
            GEOCUSTOM : "BAGEOCustom",
            BAFINGERPRINT : "BAFinPrt",
            BASESSION_ID : "BASSID",
            BASESSION_STARTTIME : "BASSSTART",
            BALASTEVENT_TIME : "BALASTEVT",
            PATHNAME : window.location.pathname,
            BATRKR : "BATRKR"
        },
        /**
         * Initialization
         */
        init : function () {
            try {
                var testKey = 'BATEST';
                var testVal = 'test';
                // Access the browser storage
                sessionStorage.setItem(testKey, testVal);
                sessionStorage.removeItem(testKey);
                localStorage.setItem(testKey, testVal);
                localStorage.removeItem(testKey);
            } catch ( e ) {
                BrowserAgent.logger.warn("storageUtils.init: Access to browser storage is denied. Browser Agent may exhibit unexpected behavior.");
                BrowserAgent.globals.isStoragePresent = false;
            }
        },
        /**
         * Stores an item in Storage
         * @param type - sessionStorage or localStorage
         * @param key
         * @param itemToStore
         * @param isIdempotent [when 'false', item will be stored only if it is not already present]
         */
        putInStorage : function ( type, key, itemToStore, isIdempotent ) {
            try {
                if ( !BrowserAgent.globals.isStoragePresent ) {
                    return;
                }
                if ( typeof key !== 'string' || itemToStore === null || itemToStore === undefined ||
                     typeof isIdempotent !== 'boolean' ) {
                    BrowserAgent.logger.warn("putInStorage: Invalid input.");
                    return;
                }
                switch ( type ) {
                    case BrowserAgent.storageUtils.storageTypes.SESSION:
                        if ( isIdempotent || (!isIdempotent && sessionStorage.getItem(key) === null) ) {
                            sessionStorage.setItem(key, itemToStore);
                        }
                        break;
                    case BrowserAgent.storageUtils.storageTypes.LOCAL:
                        if ( isIdempotent || (!isIdempotent && localStorage.getItem(key) === null) ) {
                            localStorage.setItem(key, itemToStore);
                        }
                        break;
                    default:
                        break;
                }
            } catch ( e ) {
                BrowserAgent.logger.error("putInStorage: " + e.message);
            }
        },
        /**
         * Obtains an item from Storage
         * @param type - sessionStorage or localStorage
         * @param key
         * @returns {null}
         */
        getFromStorage : function ( type, key ) {
            try {
                if ( !BrowserAgent.globals.isStoragePresent ) {
                    return null;
                }
                if ( typeof key !== 'string' ) {
                    BrowserAgent.logger.warn("getFromStorage: Invalid input.");
                    return null;
                }
                switch ( type ) {
                    case BrowserAgent.storageUtils.storageTypes.SESSION:
                        return sessionStorage.getItem(key);
                    case BrowserAgent.storageUtils.storageTypes.LOCAL:
                        return localStorage.getItem(key);
                    default:
                        return null;
                }
            } catch ( e ) {
                BrowserAgent.logger.error("getFromStorage: " + e.message);
                return null;
            }
        }
    };
    /**
     * Cookie Utility
     * Responsible for managing BrowserAgent cookies
     */
    BrowserAgent.cookieUtils = {
        /**
         * Cookies used between browser and the Agent
         */
        cookies : {
            // Response Cookie to Agent
            // Stores business txn information as sent by the agent
            BTRESP : "x-apm-brtm-response-bt",
            // Request Cookie to Agent
            // Stores an unique identifier for an instrumented AJAX call
            BTRESPID : "x-apm-brtm-response-bt-id",
            // Response Cookie from Agent
            // Stores business txn information for the current page as sent by the agent
            BTPAGERESP : "x-apm-brtm-response-bt-page",
            // Response Cookie from Agent
            // Stores server time (ms) when the response was sent. Used to calculate client server gap time
            SERVERTIME : "x-apm-brtm-servertime",
            // Request Cookie to Agent
            // Stores client server gap time (s)
            GAPTIME : "x-apm-brtm-gaptime",
            // Request Cookie to Agent
            // Stores Browser Name
            PLATFORM : "x-apm-brtm-bt-p",
            // Request cookie to agent
            // Stores browser major version
            PLATFORMVER : "x-apm-brtm-bt-pv"
        },
        /**
         * Keys inside BTRESP, BTPAGERESP as defined above
         */
        cookieKeys : {
            // Introscope txn trace start time
            apmStartTimeChar : "startTime",
            // Introscope txn trace end time
            apmEndTimeChar : "endTime",
            // Business segment
            bsChar : "bs",
            // Business txn
            btChar : "bt",
            // Business txn component
            btcChar : "btc",
            // Txn Trace Correlation ID
            CorBrowsGUIDChar : "CorBrowsGUID",
            // Geo-location
            geoChar : "g",
            // Browser name
            platformChar : "p",
            // Browser major version
            platformVerChar : "pv"
        },
        // Web pages may already have the WMRUMC (old name) cookie. Don't expect the user to clear out this cookie
        baCookieRegex : new RegExp("^x-apm-brtm-.*|^WMRUMC.*"),
        init : function () {
            // Update BS, BT context for the current page from the response cookies
            var pageBTCookieName = BrowserAgent.cookieUtils.cookies.BTPAGERESP + "-" +
                                   encodeURIComponent(window.location.pathname);
            var responseCookies = BrowserAgent.cookieUtils.getRawCookie(pageBTCookieName);
            BrowserAgent.cookieUtils.deleteCookie(pageBTCookieName, "/", null);
            if ( responseCookies ) {
                BrowserAgent.cookieUtils.updateHPDataObjWithCookieData(BrowserAgent.cookieUtils.tokenizeCookieIntoMap(responseCookies,
                                                                                                                      ','));
            } else {
                BrowserAgent.logger.warn("cookieUtils.init: Cannot get page bt cookie for url = " +
                                         window.location.pathname);
            }
            BrowserAgent.cookieUtils.deleteCookie(BrowserAgent.cookieUtils.cookies.SERVERTIME, "/",
                                                  null);
            // Get browser platform and version info
            BrowserAgent.globals.platform =
                BrowserAgent.cookieUtils.getRawCookie(BrowserAgent.cookieUtils.cookies.PLATFORM);
            BrowserAgent.globals.platformVersion =
                BrowserAgent.cookieUtils.getRawCookie(BrowserAgent.cookieUtils.cookies.PLATFORMVER);
        },
        /**
         * Delete a cookie given its name
         * Note: The path and domain must match that of the cookie at the time it was created
         * @param name - name of the cookie to be deleted
         * @param path - path of the cookie at the time it was created
         * @param domain - domain of the cookie at the time it was created
         */
        deleteCookie : function ( name, path, domain ) {
            if ( !name ) {
                BrowserAgent.logger.warn("deleteCookie : Cannot delete cookie by name " + name);
                return;
            }
            document.cookie = name + "=" + "; expires=Thu, 01-Jan-1970 00:00:01 GMT" +
                              ((domain ) ? "; domain=" + domain : "" ) +
                              ((path ) ? "; path=" + path : "");
        },
        /**
         * Given a name, obtain the corresponding cookie value
         * @param name - name of the cookie
         * @returns {*}
         */
        getRawCookie : function ( name ) {
            if ( !name ) {
                BrowserAgent.logger.warn("getRawCookie : Cannot obtain cookie " + name);
                return null;
            }
            if ( document.cookie.length > 0 ) {
                var cs = document.cookie.indexOf(name + "=");
                if ( cs !== -1 ) {
                    cs = cs + name.length + 1;
                    var ce = document.cookie.indexOf(";", cs);
                    if ( ce === -1 ) {
                        ce = document.cookie.length;
                    }
                    // Java Agent URLEncoder encodes space to "+" which is different from JavaScript
                    // encodeURIComponent. We replace "+" with "%20" here so JavaScript can decode
                    // correctly.
                    return decodeURIComponent(BrowserAgent.browserUtils.replaceAll(document.cookie.substring(cs,
                                                                                                             ce),
                                                                                   "\\+", "%20"));
                } else {
                    return null;
                }
            } else {
                return null;
            }
        },
        /**
         * Tokenize a given cookie value into a JS map
         * @param str - value of a cookie as a String
         * @param delimiter - token to split the cookie value by
         * @returns {{}}
         */
        tokenizeCookieIntoMap : function ( str, delimiter ) {
            var map = {};
            if ( !str || !delimiter ) {
                BrowserAgent.logger.warn("tokenizeCookieIntoMap : Cannot parse " + str + " by " + delimiter);
                return map;
            }
            str = str.replace(/["]/g, "");
            var lines = str.split(delimiter);
            var pieces, indexOfEq;
            for ( var i = 0; i < lines.length; i++ ) {
                pieces = lines[i].split("=");
                if ( pieces.length === 2 ) {
                    map[pieces[0]] = pieces[1];
                } else {
                    if ( pieces.length > 2 ) {
                        indexOfEq = lines[i].indexOf("=");
                        map[pieces[0]] = lines[i].substring(indexOfEq + 1);
                    }
                }
            }
            return map;
        },
        /**
         * Set a cookie into document.cookie
         * @param name - name of the cookie to be created
         * @param value - value of the cookie to be stored
         * @param expiry - the number of seconds this cookie is to
         *                 be active from the time of creation
         * @param path - path for the cookie (e.g. /)
         * @param domain - domain for the cookie
         */
        setRawCookie : function ( name, value, expiry, path, domain ) {
            if ( !name ) {
                BrowserAgent.logger.warn("setRawCookie : Cannot set cookie with name " + name);
                return;
            }
            var et = new Date(Date.now() + (expiry * 1000));
            document.cookie =
                name + "=" + encodeURIComponent(value) + ((expiry) ? "; expires=" + et.toUTCString() : "" ) +
                ((domain ) ? "; domain=" + domain : "" ) + ((path ) ? "; path=" + path : "");
        },
        /**
         * Update an existing cookie in document.cookie
         * Note: the cookie value must be a JS object
         * @param cookieName - name of the cookie that is to be updated
         * @param value - value to update with
         */
        updateCookie : function ( cookieName, value ) {
            if ( !cookieName ) {
                BrowserAgent.logger.warn("updateCookie: Cannot update cookie with name " + cookieName);
                return;
            }
            var cookieObject = JSON.parse(this.getRawCookie(cookieName));
            var newCookieObject = {};
            for ( var i in cookieObject ) {
                newCookieObject[i] = cookieObject[i];
            }
            if ( typeof value === 'object' ) {
                for ( var j in value ) {
                    if ( value[j] !== null ) {
                        newCookieObject[j] = value[j];
                    } else {
                        delete newCookieObject[j];
                    }
                }
            } else {
                newCookieObject = value;
            }
            this.setRawCookie(cookieName, JSON.stringify(newCookieObject), null, "/", null);
        },
        /**
         * Update a given object holding AJAX data with AJAX data from the cookie
         * @param cookieData - cookie data containing tokens from cookieUtils.cookieKeys
         * @param objToUpdate - a JS object containing AJAX related data
         */
        updateResDataObjWithCookieData : function ( cookieData, objToUpdate ) {
            if ( !cookieData || !objToUpdate || typeof cookieData !== 'object' ||
                 typeof objToUpdate !== 'object' ) {
                BrowserAgent.logger.warn("updateResDataObjWithCookieData: Cannot update object with data from cookie");
                return;
            }
            var key, item;
            for ( item in BrowserAgent.cookieUtils.cookieKeys ) {
                key = BrowserAgent.cookieUtils.cookieKeys[item];
                if ( cookieData[key] ) {
                    objToUpdate[key] = cookieData[key];
                    delete cookieData[key];
                }
            }
            key = BrowserAgent.globals.agentCookieKeys;
            for ( item in cookieData ) {
                if ( BrowserAgent.globals.agentCookieKeysRegexPattern.test(item) ) {
                    if ( !objToUpdate[key] ) {
                        objToUpdate[key] = {};
                    }
                    objToUpdate[key][item] = cookieData[item];
                }
            }
            // If BT matches default BT then drop all BT info
            if ( BrowserAgent.globals.defaultBTRegex.test(objToUpdate.bt) ) {
                objToUpdate.bs = BrowserAgent.globals.UNDEFINED;
                objToUpdate.bt = BrowserAgent.globals.UNDEFINED;
                objToUpdate.btc = BrowserAgent.globals.UNDEFINED;
            }
        },
        /**
         * Update a given object holding page data with page data from the cookie
         * @param cookieData - cookie data containing tokens from cookieUtils.cookiekeys
         */
        updateHPDataObjWithCookieData : function ( cookieData ) {
            if ( !cookieData || typeof cookieData !== 'object' ) {
                BrowserAgent.logger.warn("updateHPDataObjWithCookieData: Cannot update object with data from cookie");
                return;
            }
            var key, item;
            for ( item in BrowserAgent.cookieUtils.cookieKeys ) {
                key = BrowserAgent.cookieUtils.cookieKeys[item];
                if ( cookieData[key] ) {
                    BrowserAgent.globals[key] = cookieData[key];
                    delete cookieData[key];
                }
            }
            // If agent sends any response cookies starting with apm, add them to the global list
            for ( item in cookieData ) {
                if ( BrowserAgent.globals.agentCookieKeysRegexPattern.test(item) ) {
                    if ( !BrowserAgent.globals.agentCookies ) {
                        BrowserAgent.globals.agentCookies = {};
                    }
                    BrowserAgent.globals.agentCookies[item] = cookieData[item];
                }
            }
            // If BT matches default BT then drop all BT info
            if ( BrowserAgent.globals.defaultBTRegex.test(BrowserAgent.globals.bt) ) {
                BrowserAgent.globals.bs = BrowserAgent.globals.UNDEFINED;
                BrowserAgent.globals.bt = BrowserAgent.globals.UNDEFINED;
                BrowserAgent.globals.btc = BrowserAgent.globals.UNDEFINED;
            }
        },
        /**
         * Checks if cookies are enabled
         * @returns {boolean}
         */
        isCookieEnabled : function () {
            var cookieEnabled = navigator.cookieEnabled ? true : false;
            if ( navigator.cookieEnabled !== true ) {
                var cookieName = "baTestCookie";
                document.cookie = cookieName;
                cookieEnabled = (document.cookie.indexOf(cookieName) !== -1) ? true : false;
            }
            return cookieEnabled;
        },
        /**
         * Obtains a snapshot of the application cookies at the time of invocation; ignores the cookies set by BA
         * @returns {*}
         */
        getAppCookies : function () {
            if ( !BrowserAgent.cookieUtils.isCookieEnabled() ) {
                BrowserAgent.logger.warn("getAppCookies: Cannot obtain cookie snapshot because cookies are disabled.");
                return null;
            }
            var cookiePair, appCookies = {}, currentCookies;
            if ( document.cookie.length < 1 ) {
                return appCookies;
            }
            currentCookies = document.cookie.split('; ');
            // Loop through all the cookies currently present in document.cookie
            // Capture application cookies only (exclude all cookies set by BA)
            for ( var ck = 0; ck < currentCookies.length; ck++ ) {
                cookiePair = currentCookies[ck].split("=");
                if ( !BrowserAgent.cookieUtils.baCookieRegex.test(cookiePair[0]) ) {
                    // Store the value (cookiePair[0].length + 1) of the cookiePair. We need + 1 here to not
                    // include the = character
                    appCookies[cookiePair[0]] = currentCookies[ck].substring(cookiePair[0].length + 1);
                }
            }
            return appCookies;
        }
    };
    /**
     * JS Error Utility
     * Responsible for capturing JS errors
     */
    BrowserAgent.errorUtils = {
        errorKey : "jsError",
        errorType : {
            CLIENT : "CLIENT",
            NETWORK : "NETWORK",
            SUBTYPE : {
                EVAL : "EvalError",
                // Not standardized in browsers yet
                INT : "InternalError",
                RNG : "RangeError",
                REF : "ReferenceError",
                SYN : "SyntaxError",
                TYP : "TypeError",
                URI : "URIError"
            }
        },
        errorDataFields : {
            TYP : "ErrType",
            SUB : "SubType",
            MSG : "Msg",
            SRC : "File",
            LIN : "Line",
            COL : "Col",
            STK : "Stack",
            STT : "StartTime",
            DUR : "Duration"
        },
        /**
         * Error utils initialization
         */
        init : function () {
            if ( BrowserAgent.globals.configs.JSERRORSENABLED === false ) {
                BrowserAgent.logger.info("errorUtils.init: JS Error Monitoring is DISABLED.");
                return;
            }
            // Capture JS error
            BrowserAgent.logger.info("errorUtils.init: Attaching to window.onerror event...");
            window.addEventListener("error", BrowserAgent.errorUtils.captureJSError);
        },
        /**
         * The event handler to capture JS Errors from window.onerror
         * @param e
         */
        captureJSError : function ( e ) {
            try {
                if ( !e ) {
                    BrowserAgent.logger.warn("captureJSError: Could not capture error. Error object is unavailable.");
                    return;
                }
                var evtObj = BrowserAgent.evtUtils.getEvtObject(BrowserAgent.globals.evtTypes.JSERR, true,
                                                                BrowserAgent.errorUtils.errorDataFields.STT);
                if ( !evtObj ) {
                    return;
                }
                var stackTrace = null, subType = null;
                if ( e.error ) {
                    stackTrace = e.error.stack;
                    subType = BrowserAgent.errorUtils.getSubType(e.error.name, e.message);
                } else {
                    BrowserAgent.logger.warn("captureJSError : Stack information is unavailable from error object");
                    // If the error object is not present, then obtain the sub type from error message
                    subType = BrowserAgent.errorUtils.getSubType(null, e.message);
                }
                evtObj[BrowserAgent.errorUtils.errorDataFields.TYP] =
                    BrowserAgent.errorUtils.errorType.CLIENT;
                evtObj[BrowserAgent.errorUtils.errorDataFields.SUB] = subType;
                evtObj[BrowserAgent.errorUtils.errorDataFields.MSG] = e.message;
                evtObj[BrowserAgent.errorUtils.errorDataFields.SRC] = e.filename;
                evtObj[BrowserAgent.errorUtils.errorDataFields.LIN] = e.lineno;
                evtObj[BrowserAgent.errorUtils.errorDataFields.COL] = e.colno;
                evtObj[BrowserAgent.errorUtils.errorDataFields.STK] = stackTrace;
                evtObj.isDone = true;
            } catch ( err ) {
                if ( evtObj ) {
                    evtObj.isDelete = true;
                }
                BrowserAgent.logger.error("captureJSError: Could not capture JS error due to " + err.message);
            }
        },
        /**
         * Obtains JS Error sub type given the general type and the error message
         * @param type
         * @param errMsg
         * @returns {*}
         */
        getSubType : function ( type, errMsg ) {
            if ( typeof type !== 'string' ) {
                // If type is not present, then we need to parse the error message to obtain type. Naturally, if
                // the error message is not present, then do nothing
                if ( typeof errMsg !== 'string' ) {
                    BrowserAgent.logger.warn("getSubType: Could not obtain error subtype");
                    return null;
                }
                var arr = errMsg.split(":");
                if ( arr.length < 2 ) {
                    return null;
                }
                return arr[0];
            }
            return type;
        }
    };
    /**
     * Function Utility
     * Responsible for JS Function instrumentation
     */
    BrowserAgent.funcUtils = {
        tracers : {
            // Pre tracer for XMLHttpRequest.prototype.open
            'xhrOpenPre' : function () {
                try {
                    if ( !this._BAState ) {
                        this._BAState = {};
                        this._BAState.xhrOpenPre = {};
                    }
                    var stateObj = arguments[arguments.length - 1];
                    // In the XHR open call, the resource URL is a required argument
                    // Store the URL in the XHR object from which the open originates
                    // so that it can be used later to correlate metrics
                    this._BAState.xhrOpenPre.isError = false;
                    this._BAState.xhrOpenPre._isAjaxInstrumented = true;
                    if ( BrowserAgent.globals.currPagePtr.isExcluded ) {
                        this._BAState.xhrOpenPre._isAjaxInstrumented = false;
                        return;
                    }
                    this._BAState.xhrOpenPre._httpMethod = stateObj.invocationData[0];
                    this._BAState.xhrOpenPre._url = stateObj.invocationData[1];
                    this._BAState.xhrOpenPre._fullURL =
                        BrowserAgent.browserUtils.getFullURL(this._BAState.xhrOpenPre._url);
                    this._BAState.xhrOpenPre._async = true;
                    if ( arguments.length >= 3 ) {
                        this._BAState.xhrOpenPre._async = stateObj.invocationData[2];
                    }
                    this._BAState.xhrOpenPre.isAjaxEnabled = BrowserAgent.globals.configs.AJAXMETRICSENABLED;
                    this._BAState.xhrOpenPre.isAjaxExcluded =
                        BrowserAgent.configUtils.isUrlExcluded(this._BAState.xhrOpenPre._fullURL);
                    if ( !this._BAState.xhrOpenPre.isAjaxEnabled ) {
                        BrowserAgent.logger.info("xhrOpenPre: AJAX Metrics are DISABLED.");
                    }
                    if ( this._BAState.xhrOpenPre.isAjaxExcluded ) {
                        BrowserAgent.logger.info("xhrOpenPre: AJAX URL [" + this._BAState.xhrOpenPre._fullURL +
                                                 "] is configured to be EXCLUDED.");
                    }
                    if ( !this._BAState.xhrOpenPre.isAjaxEnabled || this._BAState.xhrOpenPre.isAjaxExcluded ) {
                        this._BAState.xhrOpenPre._isAjaxInstrumented = false;
                    }
                } catch ( e ) {
                    this._BAState.xhrOpenPre.isError = true;
                    BrowserAgent.logger.error("xhrOpenPre (" + this._BAState.origFunctionName + "): " + e.message);
                }
            },
            // Pre tracer for onreadystatechange
            'xhrOrscPre' : function () {
                this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.ajaxDataKeys.URL] =
                    this._BAState.xhrOpenPre._fullURL;
                this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.ajaxDataKeys.METHOD] =
                    this._BAState.xhrOpenPre._httpMethod;
                this._BAState.xhrSendPre.contentLen = BrowserAgent.funcUtils.calculateAjaxResponseSize(this);
                if ( typeof this._BAState.xhrSendPre.contentLen === 'number' ) {
                    this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.ajaxDataKeys.RESPONSE_CONTENT_LENGTH] =
                        this._BAState.xhrSendPre.contentLen;
                }
                // If First Byte time is not captured and content length is not
                // present, then set First Byte time = Last Byte time because most
                // likely the response was empty
                if ( !this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.timestampNames.FIRST_BYTE] &&
                     !this._BAState.xhrSendPre.contentLen ) {
                    this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.timestampNames.FIRST_BYTE] =
                        this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.timestampNames.LAST_BYTE];
                }
                this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.ajaxDataKeys.STATUS_CODE] = this.status;
                // Add BT information from the response Cookie
                var responseCookie = BrowserAgent.cookieUtils.getRawCookie(BrowserAgent.cookieUtils.cookies.BTRESP +
                                                                           "-" +
                                                                           this._BAState.xhrSendPre.evtObj.id);
                if ( responseCookie ) {
                    var cookieData = BrowserAgent.cookieUtils.tokenizeCookieIntoMap(responseCookie,
                                                                                    ",");
                    BrowserAgent.cookieUtils.updateResDataObjWithCookieData(cookieData,
                                                                            this._BAState.xhrSendPre.evtObj);
                }
                // No longer need the x-apm-brtm-response-bt-_uniqueID
                // cookie. So, delete it.
                BrowserAgent.cookieUtils.deleteCookie(BrowserAgent.cookieUtils.cookies.BTRESP +
                                                      "-" +
                                                      this._BAState.xhrSendPre.evtObj.id,
                                                      "/",
                                                      null);
            },
            // Pre tracer for XMLHttpRequest.prototype.send
            "xhrSendPre" : function () {
                if ( !this._BAState.xhrSendPre ) {
                    this._BAState.xhrSendPre = {};
                }
                this._BAState.xhrSendPre.isError = false;
                this._BAState.xhrSendPre.contentLen = null;
                // Wrap the Browser Agent instrumentation in a try, catch...
                try {
                    // If the XHR is used for synchronous purposes, then don't bother
                    // to trace the callbacks.
                    if ( !this._BAState.xhrOpenPre.isError && this._BAState.xhrOpenPre._isAjaxInstrumented &&
                         this._BAState.xhrOpenPre._async ) {
                        this._BAState.xhrSendPre.evtObj =
                            BrowserAgent.evtUtils.getEvtObject(BrowserAgent.globals.evtTypes.RES, false, null);
                        if ( !this._BAState.xhrSendPre.evtObj ) {
                            this._BAState.xhrSendPre.isError = true;
                        }
                        BrowserAgent.cookieUtils.setRawCookie(BrowserAgent.cookieUtils.cookies.BTRESPID,
                                                              this._BAState.xhrSendPre.evtObj.id, 2, "/",
                                                              null);
                        // Get request body size
                        this._BAState.xhrSendPre.bodySize =
                            BrowserAgent.funcUtils.calculateAjaxRequestSize(arguments[0]);
                        if ( !this._BAState.xhrSendPre.isError && this._BAState.xhrSendPre.bodySize ) {
                            this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.ajaxDataKeys.REQUEST_BODY_SIZE] =
                                this._BAState.xhrSendPre.bodySize;
                        }
                        var origOnloadEnd = this.onloadend, origOrsc = this.onreadystatechange, origOnload = this.onload;
                        // Redefine xhr.onload
                        this.onload = function () {
                            var retVal;
                            if ( origOnload ) {
                                try {
                                    var now = Date.now();
                                    if ( !this._BAState.xhrSendPre.isError ) {
                                        // For, jQuery 1.x, set other AJAX instance data here
                                        if ( BrowserAgent.globals.isJQOne &&
                                             !this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.ajaxDataKeys.URL] ) {
                                            BrowserAgent.funcUtils.tracers.xhrOrscPre.apply(this, arguments);
                                            // Set the CBK start time, if not already present
                                            if ( origOnload._origFlag &&
                                                 !this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.timestampNames.CALLBACK_START_TIME] ) {
                                                this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.timestampNames.CALLBACK_START_TIME] =
                                                    now;
                                            }
                                        } else if ( !this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.timestampNames.CALLBACK_START_TIME] ) {
                                            // Set the CBK start time, if not already present
                                            this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.timestampNames.CALLBACK_START_TIME] =
                                                now;
                                        }
                                    }
                                } catch ( e ) {
                                    this._BAState.xhrSendPre.isError = true;
                                    BrowserAgent.logger.error("xhrSendPre - onload pre (" +
                                                              this._BAState.xhrOpenPre._fullURL + "): " +
                                                              e.message);
                                }
                                ///////////// Start of ORIGINAL ONLOAD ////////////
                                retVal = origOnload.apply(this, arguments);
                                ///////////// End of ORIGINAL ONLOAD /////////////
                            }
                            return retVal;
                        };
                        // Redefine xhr.onloadend
                        this.onloadend = function () {
                            var retVal;
                            if ( origOnloadEnd ) {
                                try {
                                    // Set the CBK start time, if not already present
                                    // If already present, then xhr.onload or xhr.onreadystatechange is defined by the
                                    // application. So, take that as the start of the CBK
                                    if ( !this._BAState.xhrSendPre.isError &&
                                         !this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.timestampNames.CALLBACK_START_TIME] ) {
                                        this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.timestampNames.CALLBACK_START_TIME] =
                                            Date.now();
                                    }
                                } catch ( e ) {
                                    this._BAState.xhrSendPre.isError = true;
                                    if ( this._BAState.xhrSendPre.evtObj ) {
                                        this._BAState.xhrSendPre.evtObj.isDelete = true;
                                    }
                                    BrowserAgent.logger.error("xhrSendPre - onloadend pre (" +
                                                              this._BAState.xhrOpenPre._fullURL + "): " +
                                                              e.message);
                                }
                                ///////////// Start of ORIGINAL ONLOADEND ////////////
                                retVal = origOnloadEnd.apply(this, arguments);
                                ///////////// End of ORIGINAL ONLOADEND /////////////
                            }
                            // Set the CBK end time here.
                            // As per XHR RFC, onloadend is called in both success and failure scenarios, except
                            // timeout and abort (Whooptidoo, we don't care about these callbacks for now)
                            try {
                                if ( !this._BAState.xhrSendPre.isError &&
                                     !this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.timestampNames.CALLBACK_END_TIME] ) {
                                    this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.timestampNames.CALLBACK_END_TIME] =
                                        Date.now();
                                }
                            } catch ( e ) {
                                this._BAState.xhrSendPre.isError = true;
                                if ( this._BAState.xhrSendPre.evtObj ) {
                                    this._BAState.xhrSendPre.evtObj.isDelete = true;
                                }
                                BrowserAgent.logger.error("xhrSendPre - onloadend post (" +
                                                          this._BAState.xhrOpenPre._fullURL + "): " +
                                                          e.message);
                            }
                            this._BAState.xhrSendPre.evtObj.isDone = true;
                            return retVal;
                        };
                        // Redefine xhr.onreadystatechange
                        this.onreadystatechange = function () {
                            var retVal;
                            // Wrap the Browser Agent instrumentation in a try, catch...
                            try {
                                if ( !this._BAState.xhrSendPre.isError ) {
                                    if ( this.readyState === this.LOADING ) {
                                        // time it on first invocation, not all
                                        this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.timestampNames.FIRST_BYTE] =
                                            Date.now();
                                    }
                                    if ( this.readyState === this.DONE ) {
                                        this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.timestampNames.LAST_BYTE] =
                                            Date.now();
                                        BrowserAgent.funcUtils.tracers.xhrOrscPre.apply(this, arguments);
                                    }
                                }
                            } catch ( e ) {
                                this._BAState.xhrSendPre.isError = true;
                                if ( this._BAState.xhrSendPre.evtObj ) {
                                    this._BAState.xhrSendPre.evtObj.isDelete = true;
                                }
                                BrowserAgent.logger.error("xhrSendPre - orsc pre - 1 (" +
                                                          this._BAState.xhrOpenPre._fullURL + "): " + e.message);
                            }
                            if ( origOrsc ) {
                                // Mark the CBK start time
                                try {
                                    if ( !this._BAState.xhrSendPre.isError && this.readyState === this.DONE &&
                                         !this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.timestampNames.CALLBACK_START_TIME] ) {
                                        this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.timestampNames.CALLBACK_START_TIME] =
                                            Date.now();
                                    }
                                } catch ( e ) {
                                    this._BAState.xhrSendPre.isError = true;
                                    BrowserAgent.logger.error("xhrSendPre - orsc pre - 2 (" +
                                                              this._BAState.xhrOpenPre._fullURL + "): " +
                                                              e.message);
                                }
                                ///////////// Start of ORIGINAL ONREADYSTATECHANGE ////////////
                                retVal = origOrsc.apply(this, arguments);
                                ///////////// End of ORIGINAL ONREADYSTATECHANGE /////////////
                            }
                            return retVal;
                        };
                    }
                } catch ( e ) {
                    this._BAState.xhrSendPre.isError = true;
                    if ( this._BAState.xhrSendPre.evtObj ) {
                        this._BAState.xhrSendPre.evtObj.isDelete = true;
                    }
                    BrowserAgent.logger.error("xhrSendPre (" + this._BAState.xhrOpenPre._fullURL + "): " +
                                              e.message);
                }
            },
            // Post tracer for XMLHttpRequest.prototype.send
            "xhrSendPost" : function () {
                // Wrap the rest of the Browser Agent instrumentation in a try, catch...
                try {
                    // If XHR is used for synchronous purposes, don't bother to record
                    // Ajax data point
                    if ( !this._BAState.xhrSendPre.isError && this._BAState.xhrOpenPre._isAjaxInstrumented &&
                         this._BAState.xhrOpenPre._async ) {
                        // Mark the end time of XHR send, which is in fact the start time of the ajax call and
                        // clone the current tracker data into a list to the instance
                        this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.timestampNames.END_TIME] = Date.now();
                        this._BAState.xhrSendPre.evtObj[BrowserAgent.globals.trackerDataKey] =
                            BrowserAgent.browserUtils.cloneTrackerData();
                    }
                } catch ( e ) {
                    if ( this._BAState.xhrSendPre.evtObj ) {
                        this._BAState.xhrSendPre.evtObj.isDelete = true;
                    }
                    BrowserAgent.logger.error("xhrSendPost (" + this._BAState.xhrOpenPre._fullURL + "): " +
                                              e.message);
                }
            },
            // Pre tracer to mark the start time of a JS Function to provide JS Function metrics
            "JSFuncPre" : function () {
                var stateObj = arguments[arguments.length - 1];
                // Wrap the Browser Agent instrumentation in a try, catch...
                try {
                    if ( !stateObj.JSFuncPre ) {
                        stateObj.JSFuncPre = {};
                    }
                    stateObj.JSFuncPre.isError = false;
                    stateObj.JSFuncPre.isFuncEnabled = BrowserAgent.globals.configs.JSFUNCTIONMETRICSENABLED;
                    if ( !stateObj.JSFuncPre.isFuncEnabled ) {
                        BrowserAgent.logger.info("JSFuncPre (" + stateObj.origFunctionName +
                                                 "): JS Function Metrics are DISABLED.");
                    } else {
                        stateObj.JSFuncPre.evtObj =
                            BrowserAgent.evtUtils.getEvtObject(BrowserAgent.globals.evtTypes.FN, false,
                                                               BrowserAgent.globals.timestampNames.START_TIME);
                        if ( !stateObj.JSFuncPre.evtObj ) {
                            stateObj.JSFuncPre.isError = true;
                        }
                    }
                } catch ( e ) {
                    stateObj.JSFuncPre.isError = true;
                    if ( stateObj.JSFuncPre.evtObj ) {
                        stateObj.JSFuncPre.evtObj.isDelete = true;
                    }
                    BrowserAgent.logger.error("JSFuncPre (" + stateObj.origFunctionName + "): " +
                                              e.message);
                }
            },
            // Post tracer to mark the end time of a JS Function to provide JS Function metrics
            "JSFuncPost" : function () {
                // Wrap the rest of the Browser Agent instrumentation in a try, catch...
                var stateObj = arguments[arguments.length - 1];
                try {
                    if ( !stateObj.JSFuncPre.isError && stateObj.JSFuncPre.isFuncEnabled ) {
                        // Clone the current tracker data map into a list to the instance
                        // Note: We need to clone tracker data here rather than in 'JSFuncPre' pre tracer
                        // because it is very possible that a customer might have invoked the AXA extension APIs in
                        // the original function
                        stateObj.JSFuncPre.evtObj[BrowserAgent.globals.trackerDataKey] =
                            BrowserAgent.browserUtils.cloneTrackerData();
                        stateObj.JSFuncPre.evtObj[BrowserAgent.globals.timestampNames.END_TIME] = Date.now();
                        stateObj.JSFuncPre.evtObj.fnName = stateObj.origFunctionName;
                        stateObj.JSFuncPre.evtObj.isDone = true;
                    }
                } catch ( e ) {
                    if ( stateObj.JSFuncPre.evtObj ) {
                        stateObj.JSFuncPre.evtObj.isDelete = true;
                    }
                    BrowserAgent.logger.error("JSFuncPost (" + stateObj.origFunctionName + "): " +
                                              e.message);
                }
            },
            "routeChangePre" : function () {
                var stateObj = arguments[arguments.length - 1];
                try {
                    if ( !BrowserAgent.globals.configs.PAGELOADMETRICSENABLED ) {
                        BrowserAgent.logger.info("routeChangePre: Soft Page Metrics are DISABLED.");
                        return;
                    }
                    if ( !stateObj.routeChangePre ) {
                        stateObj.routeChangePre = {};
                    }
                    // Set soft navigation start
                    stateObj.routeChangePre[BrowserAgent.globals.softPageDataKeys.START] = Date.now();
                    stateObj.routeChangePre[BrowserAgent.globals.trackerDataKey] =
                        BrowserAgent.browserUtils.cloneTrackerData();
                    stateObj.routeChangePre.isError = false;
                    if ( BrowserAgent.globals.domChangeTimeoutId || BrowserAgent.globals.domChangeTimerId ) {
                        // Still tracking DOM changes from last route change. End it.
                        BrowserAgent.logger.debug(stateObj.origFunctionName +
                                                  " routeChangePre: DOM change tracking terminated by new route change.");
                        BrowserAgent.pageUtils.endDomTracking(stateObj.routeChangePre[BrowserAgent.globals.softPageDataKeys.START]);
                    }
                } catch ( e ) {
                    stateObj.routeChangePre.isError = true;
                    BrowserAgent.logger.error("routeChangePre (" + stateObj.origFunctionName + "): " + e.message);
                }
            },
            "routeChangePost" : function () {
                var stateObj = arguments[arguments.length - 1];
                try {
                    // Create a new SP Bucket
                    BrowserAgent.pageUtils.addNewPageBucket(BrowserAgent.globals.pageBucketTypes.SP,
                                                            window.location.href,
                                                            stateObj.routeChangePre[BrowserAgent.globals.softPageDataKeys.START],
                                                            true,
                                                            stateObj.routeChangePre[BrowserAgent.globals.trackerDataKey]);
                    if ( !BrowserAgent.globals.isSoftPageLoad ) {
                        return;
                    }
                    if ( !stateObj.routeChangePre.isError ) {
                        BrowserAgent.pageUtils.startDomTracking(stateObj.routeChangePre[BrowserAgent.globals.softPageDataKeys.START],
                                                                stateObj.routeChangePre[BrowserAgent.globals.trackerDataKey]);
                    }
                } catch ( e ) {
                    BrowserAgent.logger.error("routeChangePost (" + stateObj.origFunctionName + "): " + e.message);
                }
            },
            "jQuery.ajaxSettings.xhrPost" : function () {
                var stateObj = arguments[arguments.length - 1];
                try {
                    if ( BrowserAgent.globals.isJQ === false ) {
                        return;
                    }
                    if ( !stateObj.jQXhrPost ) {
                        stateObj.jQXhrPost = {};
                    }
                    if ( typeof BrowserAgent.globals.isJQ !== 'boolean' ) {
                        BrowserAgent.browserUtils.isJQPresent();
                    }
                    if ( BrowserAgent.globals.isJQOne === true ) {
                        // The return value of the original function to which this function is attached, will return
                        // the xhr instance for the current AJAX Call. Here, we need to attach onload handler to this
                        // instance
                        // Take a look at jQuery 1.x source code (jQuery.ajaxSettings.xhr):
                        // https://github.com/jquery/jquery/blob/master/src/ajax/xhr.js
                        var xhr = stateObj.funcRetVal;
                        var origOnload = xhr.onload;
                        // Even if the original onload handler is not defined, we want an onload handler defined
                        // because other metrics such as request size, response size, etc need to be calculated inside
                        // the onload handler as onreadystatechange is short circuited in jQuery 1.x
                        xhr.onload = function () {
                            if ( origOnload ) {
                                // Since the onload handler will be defined even if the original onload is not present
                                // for jQuery 1.x, this flag will prevent BA from calculating CBK execution time when
                                // original onload is not defined
                                origOnload._origFlag = true;
                                origOnload.apply(this, arguments);
                            }
                        };
                    }
                    // Do the following only once
                    if ( stateObj.jQXhrPost.isVisited === true ) {
                        return;
                    }
                    $.ajaxPrefilter(function ( options, originalOptions, jqXHR ) {
                        options._evtInfo = {};
                        options._evtInfo.evtId = BrowserAgent.globals.peekSequenceNum();
                        options._evtInfo.pageId = BrowserAgent.globals.currPagePtr.id;
                        var _origSuccCbk = originalOptions.success, _origCompleteCbk = originalOptions.complete, retVal;
                        if ( _origSuccCbk ) {
                            options.success = function ( data, textStatus, jqXHR ) {
                                var evtObj;
                                try {
                                    evtObj =
                                        BrowserAgent.globals.pageBucketsMap[this._evtInfo.pageId].evtMap[this._evtInfo.evtId];
                                    if ( evtObj ) {
                                        evtObj[BrowserAgent.globals.timestampNames.CALLBACK_START_TIME] = Date.now();
                                    }
                                } catch ( e ) {
                                    stateObj.jQXhrPost.isError = true;
                                    BrowserAgent.logger.error("jQuery.ajaxSettings.xhrPost - Success Pre (" +
                                                              stateObj.origFunctionName + "): " + e.message);
                                }

                                ///////////// Start of ORIGINALjQuery.ajax.success ////////////
                                retVal = _origSuccCbk.apply(this, arguments);
                                /////////// End of ORIGINAL jQuery.ajax.success //////////////

                                try {
                                    if ( !stateObj.jQXhrPost.isError && evtObj ) {
                                        evtObj[BrowserAgent.globals.timestampNames.CALLBACK_END_TIME] = Date.now();
                                    }
                                } catch ( e ) {
                                    stateObj.jQXhrPost.isError = true;
                                    BrowserAgent.logger.error("jQuery.ajaxSettings.xhrPost - Success Post (" +
                                                              stateObj.origFunctionName + "): " + e.message);
                                }
                                return retVal;
                            };
                        }
                        if ( _origCompleteCbk ) {
                            options.complete = function ( jqXHR, textStatus ) {
                                var evtObj, retVal;
                                try {
                                    evtObj =
                                        BrowserAgent.globals.pageBucketsMap[this._evtInfo.pageId].evtMap[this._evtInfo.evtId];
                                    if ( !stateObj.jQXhrPost.isError && evtObj &&
                                         !evtObj[BrowserAgent.globals.timestampNames.CALLBACK_START_TIME] ) {
                                        evtObj[BrowserAgent.globals.timestampNames.CALLBACK_START_TIME] = Date.now();
                                    }
                                } catch ( e ) {
                                    stateObj.jQXhrPost.isError = true;
                                    BrowserAgent.logger.error("jQuery.ajaxSettings.xhrPost - Complete Pre (" +
                                                              stateObj.origFunctionName + "): " + e.message);
                                }

                                ///////////// Start of ORIGINALjQuery.ajax.success ////////////
                                retVal = _origCompleteCbk.apply(this, arguments);
                                /////////// End of ORIGINAL jQuery.ajax.success //////////////

                                try {
                                    if ( !stateObj.jQXhrPost.isError && evtObj ) {
                                        evtObj[BrowserAgent.globals.timestampNames.CALLBACK_END_TIME] = Date.now();
                                    }
                                } catch ( e ) {
                                    stateObj.jQXhrPost.isError = true;
                                    BrowserAgent.logger.error("jQuery.ajaxSettings.xhrPost - Complete Post (" +
                                                              stateObj.origFunctionName + "): " + e.message);
                                }
                                return retVal;
                            };
                        }
                    });
                    stateObj.jQXhrPost.isVisited = true;
                } catch ( e ) {
                    BrowserAgent.logger.error("jQuery.ajaxSettings.xhrPost (" + stateObj.origFunctionName + "): " +
                                              e.message);
                }
            }
        },
        /**
         * Function utils initialization
         */
        init : function () {
            ////////////////////////// EXTENSION POINT [extAddJSFuncToInstrument] //////////////////////////
            // Add all of them to a map. Key : function name.
            if ( typeof BrowserAgentExtension !== 'undefined' ) {
                BrowserAgentExtension.extAddJSFuncToInstrument();
            }
            // Add the internal instrumentation for XHR functions to the global instrument list
            BrowserAgent.funcUtils.addFuncToCollection(BrowserAgent.globals.functionsToInstrumentList,
                                                       "XMLHttpRequest.prototype.open",
                [{
                    name : "BrowserAgent.funcUtils.tracers.xhrOpenPre",
                    func : BrowserAgent.funcUtils.tracers.xhrOpenPre
                }]);
            BrowserAgent.funcUtils.addFuncToCollection(BrowserAgent.globals.functionsToInstrumentList,
                                                       "XMLHttpRequest.prototype.send",
                [{
                    name : "BrowserAgent.funcUtils.tracers.xhrSendPre",
                    func : BrowserAgent.funcUtils.tracers.xhrSendPre
                }], [{
                    name : "BrowserAgent.funcUtils.tracers.xhrSendPost",
                    func : BrowserAgent.funcUtils.tracers.xhrSendPost
                }]);
            // Add the internal instrumentation for soft page route change to the global instrument list
            if ( window.history && window.MutationObserver ) {
                BrowserAgent.funcUtils.addFuncToCollection(BrowserAgent.globals.functionsToInstrumentList,
                                                           "history.pushState",
                    [{
                        name : "BrowserAgent.funcUtils.tracers.routeChangePre",
                        func : BrowserAgent.funcUtils.tracers.routeChangePre
                    }], [{
                        name : "BrowserAgent.funcUtils.tracers.routeChangePost",
                        func : BrowserAgent.funcUtils.tracers.routeChangePost
                    }]);
                BrowserAgent.funcUtils.addFuncToCollection(BrowserAgent.globals.functionsToInstrumentList,
                                                           "history.replaceState",
                    [{
                        name : "BrowserAgent.funcUtils.tracers.routeChangePre",
                        func : BrowserAgent.funcUtils.tracers.routeChangePre
                    }], [{
                        name : "BrowserAgent.funcUtils.tracers.routeChangePost",
                        func : BrowserAgent.funcUtils.tracers.routeChangePost
                    }]);
            }
            // jQuery 1.x AJAX Instrumentation
            BrowserAgent.funcUtils.addFuncToCollection(BrowserAgent.globals.functionsToInstrumentList,
                                                       "jQuery.ajaxSettings.xhr", null, [{
                    name : "BrowserAgent.funcUtils.tracers.jQuery.ajaxSettings.xhrPost",
                    func : BrowserAgent.funcUtils.tracers["jQuery.ajaxSettings.xhrPost"]
                }]);

            // Now, go through the global instrument list and see if the function the customer asked to be
            // instrumented is one of the Internal functions. If so, add pre and post tracers accordingly
            BrowserAgent.funcUtils.constructInstrumentFunctionList();
            // Instrument the JS functions that were added above
            BrowserAgent.funcUtils.instrumentAllFunc();
        },
        /**
         * Obtains the JS function from the window scope
         * @param funcName
         * @returns {*}
         */
        getFuncFromWindowScope : function ( funcName ) {
            try {
                return eval("window." + funcName + ";");
            } catch ( e ) {
                // Do nothing
            }
            return null;
        },
        /**
         * Constructs the list of functions to be instrumented by BA
         * Adds both functions that BA wants to instrument as well as functions given by the end user from the
         * extAddJSFuncToInstrument extension point
         */
        constructInstrumentFunctionList : function () {
            var i, j, k, item, origFuncFromWindow, func, finalPre, finalPost, jsFuncPreObj, jsFuncPostObj;
            jsFuncPreObj = {
                name : "BrowserAgent.funcUtils.tracers.JSFuncPre",
                func : BrowserAgent.funcUtils.tracers.JSFuncPre
            };
            jsFuncPostObj = {
                name : "BrowserAgent.funcUtils.tracers.JSFuncPost",
                func : BrowserAgent.funcUtils.tracers.JSFuncPost
            };
            for ( i = 0; i < BrowserAgent.globals.functionsToInstrumentList.length; i++ ) {
                func = BrowserAgent.globals.functionsToInstrumentList[i];
                item = BrowserAgent.globals.extFuncMap[func.name];
                finalPre = [];
                // If the function from the global instrument list is also in the extension function map, then
                // append 'pre' tracer and 'post' tracer lists
                if ( item && !item.visited ) {
                    for ( j = 0; j < item.pre.length; j++ ) {
                        origFuncFromWindow = BrowserAgent.funcUtils.getFuncFromWindowScope(item.pre[j].name);
                        if ( !origFuncFromWindow ) {
                            BrowserAgent.logger.warn("constructInstrumentFunctionList - 1: Could not find pre tracer [" +
                                                     item.pre[j].name + "] for JS Function [" + func.name +
                                                     "] in global scope.");
                            continue;
                        }
                        item.pre[j].func = origFuncFromWindow;
                        finalPre.push(item.pre[j]);
                    }
                    BrowserAgent.globals.functionsToInstrumentList[i].pre =
                        BrowserAgent.globals.functionsToInstrumentList[i].pre.concat(finalPre);
                    finalPost = [];
                    for ( j = 0; j < item.post.length; j++ ) {
                        origFuncFromWindow = BrowserAgent.funcUtils.getFuncFromWindowScope(item.post[j].name);
                        if ( !origFuncFromWindow ) {
                            BrowserAgent.logger.warn("constructInstrumentFunctionList - 2: Could not find post tracer [" +
                                                     item.post[j].name + "] for JS Function [" + func.name +
                                                     "] in global scope.");
                            continue;
                        }
                        item.post[j].func = origFuncFromWindow;
                        finalPost.push(item.post[j]);
                    }
                    BrowserAgent.globals.functionsToInstrumentList[i].pre.push(jsFuncPreObj);
                    // For pushState and replaceState, we want the routeChangePost to happen as the first post
                    // tracer to reduce the chance of missing DOM changes.
                    if ( func.name === "history.pushState" || func.name === "history.replaceState" ) {
                        BrowserAgent.globals.functionsToInstrumentList[i].post.push(jsFuncPostObj);
                        BrowserAgent.globals.functionsToInstrumentList[i].post =
                            BrowserAgent.globals.functionsToInstrumentList[i].post.concat(finalPost);
                    } else {
                        BrowserAgent.globals.functionsToInstrumentList[i].post =
                            BrowserAgent.globals.functionsToInstrumentList[i].post.concat(finalPost);
                        BrowserAgent.globals.functionsToInstrumentList[i].post.unshift(jsFuncPostObj);
                    }
                    item.visited = true;
                }
            }
            // Add all the non-colliding functions from the extension map to the global list
            for ( k in BrowserAgent.globals.extFuncMap ) {
                item = BrowserAgent.globals.extFuncMap[k];
                if ( item.visited ) {
                    continue;
                }
                finalPre = [];
                for ( j = 0; j < item.pre.length; j++ ) {
                    origFuncFromWindow = BrowserAgent.funcUtils.getFuncFromWindowScope(item.pre[j].name);
                    if ( !origFuncFromWindow ) {
                        BrowserAgent.logger.warn("constructInstrumentFunctionList - 3: Could not find pre tracer [" +
                                                 item.pre[j].name + "] for JS Function [" + k +
                                                 "] in global scope.");
                        continue;
                    }
                    item.pre[j].func = origFuncFromWindow;
                    finalPre.push(item.pre[j]);
                }
                finalPost = [];
                for ( j = 0; j < item.post.length; j++ ) {
                    origFuncFromWindow = BrowserAgent.funcUtils.getFuncFromWindowScope(item.post[j].name);
                    if ( !origFuncFromWindow ) {
                        BrowserAgent.logger.warn("constructInstrumentFunctionList - 4: Could not find post tracer [" +
                                                 item.post[j].name + "] for JS Function [" + k +
                                                 "] in global scope.");
                        continue;
                    }
                    item.post[j].func = origFuncFromWindow;
                    finalPost.push(item.post[j]);
                }
                var obj = {};
                obj.name = k;
                obj.pre = finalPre;
                obj.post = finalPost;
                obj.pre.push(jsFuncPreObj);
                obj.post.unshift(jsFuncPostObj);
                BrowserAgent.globals.functionsToInstrumentList.push(obj);
                item.visited = true;
            }
        },
        /**
         * If the collection is an array, then appends an object of the form { name: funcName, pre: preTracerList,
             * post: postTracerList } If the collection is a JS object, then sets an object of the form { pre:
             * preTracerList, post: postTracerList } with funcName as key
         * @param collection
         * @param funcName
         * @param preTracerList
         * @param postTracerList
         */
        addFuncToCollection : function ( collection, funcName, preTracerList, postTracerList ) {
            var type = BrowserAgent.browserUtils.getObjType(collection);
            if ( type !== 'Array' && type !== 'Object' ) {
                BrowserAgent.logger.warn("addFuncToCollection: collection [" + collection +
                                         "] must be an array or a map");
                return;
            }
            if ( type === 'Object' && collection[funcName] ) {
                BrowserAgent.logger.warn("addFuncToCollection: JS Function [" + funcName +
                                         "] will NOT be added as it is already present.");
                return;
            }
            if ( typeof funcName !== 'string' || funcName.length < 1 ) {
                BrowserAgent.logger.warn("addFuncToCollection: Could not add JS Function because function name [" +
                                         funcName + "] is invalid.");
                return;
            }
            var obj = {};
            if ( BrowserAgent.browserUtils.getObjType(preTracerList) === 'Array' ) {
                obj.pre = preTracerList;
            } else {
                BrowserAgent.logger.info("addFuncToCollection: Found invalid or unspecified preTracerList for JS Function [" +
                                         funcName + "]. Defaulting to [].");
                obj.pre = [];
            }
            if ( BrowserAgent.browserUtils.getObjType(postTracerList) === 'Array' ) {
                obj.post = postTracerList;
            } else {
                BrowserAgent.logger.info("addFuncToCollection: Found invalid or unspecified postTracerList for JS Function [" +
                                         funcName + "]. Defaulting to [].");
                obj.post = [];
            }
            if ( type === 'Array' ) {
                obj.name = funcName;
                collection.push(obj);
            } else {
                collection[funcName] = obj;
            }
        },
        /**
         * Calculates ajax request body size.
         * Supports String, Blob, File, ArrayBuffer, DataView.
         * @param body
         * @returns number or null
         */
        calculateAjaxRequestSize : function ( body ) {
            var type = BrowserAgent.browserUtils.getObjType(body);
            var size = null;
            if ( type === 'String' ) {
                size = body.length;
            } else if ( type === 'Blob' || type === 'File' ) {
                size = body.size;
            } else if ( type === 'ArrayBuffer' || type === 'DataView' ) {
                size = body.byteLength;
            }
            return size;
        },
        /**
         * Calculates ajax response size
         * @param xhrObject
         * @returns {*}
         */
        calculateAjaxResponseSize : function ( xhrObject ) {
            var size = null;
            // This block needs a try catch because if this fails (highly unlikely) then the rest of the
            // Ajax instrumentation fails, which is undesirable
            try {
                var responseHeaders = xhrObject.getAllResponseHeaders();
                var responseType = xhrObject.responseType;

                // You would think that the spec is Content-Length. No. It accepts lower case
                // content-length as well
                var contentLenIdx = responseHeaders.indexOf(BrowserAgent.globals.contentLengthHdrStr) ||
                                    responseHeaders.indexOf(BrowserAgent.globals.contentLengthHdrStrLowerCase);
                if ( contentLenIdx !== -1 ) {
                    // If content length is found, then split on '\n' would make the 'content-length'
                    // header
                    // appear as the first element of the resulting array. Then, a further split on ': '
                    // would make the value of the length appear as the second element of this resultant
                    // array
                    size = Number(responseHeaders.substring(contentLenIdx).split(/\n/)[0].split(/:\s*/)[1]);
                } else if ( responseType === "" || responseType === "text" ) {
                    // If the responseType is not text, then we can run into trouble because string
                    // representation of images, binary objects, etc ... would not give accurate sizing
                    // Note: Can only access xhrObject.responseText when responseType is either "" or "text"
                    size = xhrObject.responseText ? xhrObject.responseText.length : null;
                }
            } catch ( e ) {
                BrowserAgent.logger.warn("calculateAjaxResponseSize: Unable to obtain content length due to " +
                                         e.message);
                size = null;
            }
            return size;
        },
        /**
         * Instruments a given JS Function by redefining it with Browser Agent logic.
         * @param funcName
         * @param preTracerList
         * @param postTracerList
         * @param maxRetryCount
         * @param isTriedAlready
         * @returns {*}
         */
        instrumentFunc : function ( funcName, preTracerList, postTracerList, maxRetryCount, isTriedAlready ) {
            var origFuncFromWindow = BrowserAgent.funcUtils.getFuncFromWindowScope(funcName);
            // Needless to say, if the original function is not in scope, there is nothing to do
            // So, Skip the instrumentation
            if ( !origFuncFromWindow ) {
                // Don't flood the logs with this message
                // 1. For long list of functions to instrument, this will flood the logs
                // 2. For features / frameworks that only exist in certain frameworks, functions may not exist in all
                // pages. So, retry will be invoked and these log statements will flood the logs
                if ( !isTriedAlready ) {
                    BrowserAgent.logger.warn("instrumentFunc: JS Function [" + funcName +
                                             "] could not be found in the browser window scope. Scheduling retry...");
                }
                BrowserAgent.funcUtils.retryInstrumentFunc(funcName, preTracerList, postTracerList,
                                                           maxRetryCount);
                return null;
            }
            // If the function is already instrumented, don't bother to instrument it
            if ( origFuncFromWindow._BAState && origFuncFromWindow._BAState.isInstrumented ) {
                BrowserAgent.logger.info("instrumentFunc: JS Function [" + funcName +
                                         "] already instrumented. Skipping instrumentation...");
                return null;
            }
            BrowserAgent.funcUtils.saveOrigObj(funcName, origFuncFromWindow);
            // If the function was not saved in the original function map, then don't
            // proceed with instrumentation
            if ( !BrowserAgent.globals.origFuncMap || !BrowserAgent.globals.origFuncMap[funcName] ) {
                BrowserAgent.logger.warn("instrumentFunc: JS Function [" + funcName +
                                         "] could not be saved. Skipping instrumentation...");
                return null;
            }
            BrowserAgent.logger.info("instrumentFunc: Instrumenting JS Function [" + funcName + "]...");
            var redefinedFunc = function () {
                var i;
                var args = [];
                var isError = false;
                // Super defensive, just in case users do not use try catch blocks in their tracers
                try {
                    // Save the original arguments. Might be useful to retrieve for real name formatting and tracers
                    redefinedFunc._BAState.invocationData = arguments;
                    for ( i = 0; i < preTracerList.length; i++ ) {
                        if ( preTracerList[i].args ) {
                            args = preTracerList[i].args;
                        }
                        // Also, append the reference to _BAState so that state can be maintained across tracers
                        args.push(redefinedFunc._BAState);
                        preTracerList[i].func.apply(this, args);
                    }
                } catch ( e ) {
                    isError = true;
                    BrowserAgent.logger.error("instrumentFunc: Error in pre tracer(s) for JS Function [" +
                                              funcName + "] - " + e.message);
                }

                //////////////// Start of ORIGINAL JS Function ////////////////
                var funcRet = origFuncFromWindow.apply(this, arguments);
                //////////////// End of ORIGINAL JS Function ////////////////

                // Super defensive, just in case users do not use try catch blocks in their tracers
                try {
                    redefinedFunc._BAState.funcRetVal = funcRet;
                    if ( isError ) {
                        return funcRet;
                    }
                    for ( i = 0; i < postTracerList.length; i++ ) {
                        if ( postTracerList[i].args ) {
                            args = postTracerList[i].args;
                        }
                        // Also, append the reference to _BAState so that state can be maintained across tracers
                        args.push(redefinedFunc._BAState);
                        postTracerList[i].func.apply(this, args);
                    }
                } catch ( e ) {
                    BrowserAgent.logger.error("instrumentFunc: Error in post tracer(s) for JS Function [" +
                                              funcName + "] - " + e.message);
                }
                return funcRet;
            };
            if ( redefinedFunc ) {
                redefinedFunc._BAState = {};
                redefinedFunc._BAState.isInstrumented = true;
                redefinedFunc._BAState.origFunctionName = funcName;
            }
            BrowserAgent.logger.info("instrumentFunc: Finished instrumentation for JS Function [" + funcName +
                                     "].");
            // Remove the setTimeout ID
            if ( BrowserAgent.globals.retryFuncIdMap[funcName] ) {
                delete BrowserAgent.globals.retryFuncIdMap[funcName];
            }
            return redefinedFunc;
        },
        /**
         * Retry the instrumentation of a js function for a maximum of 5 times with at least 5 seconds interval
         * @param funcName
         * @param pre
         * @param post
         * @param maxRetryCount
         */
        retryInstrumentFunc : function ( funcName, pre, post, maxRetryCount ) {
            // Instrumentation could fail if the JS Function to instrument
            // has not come into the window's scope yet. As an example, consider function
            // A() in another file that would be downloaded from a CDN at a later time than
            // our Browser Agent JS code. So, we retry the instrumentation for N number of times.
            if ( maxRetryCount < 0 ) {
                BrowserAgent.logger.warn("retryInstrumentFunc: Well, this is embarrassing. JS Function [" +
                                         funcName +
                                         "] could not be instrumented as it is not found even after several retries.");
                // Remove the setTimeout ID
                if ( BrowserAgent.globals.retryFuncIdMap[funcName] ) {
                    delete BrowserAgent.globals.retryFuncIdMap[funcName];
                }
            } else {
                BrowserAgent.globals.retryFuncIdMap[funcName] = setTimeout(function () {
                    BrowserAgent.funcUtils.assignFunc(funcName,
                                                      BrowserAgent.funcUtils.instrumentFunc(funcName,
                                                                                            pre, post,
                                                                                            maxRetryCount -
                                                                                            1, true));
                }, BrowserAgent.globals.retryInterval);
            }
        },
        /**
         * Instrument all the functions in BrowserAgent.globals.functionsToInstrumentList
         */
        instrumentAllFunc : function () {
            if ( !BrowserAgent.globals.functionsToInstrumentList ) {
                BrowserAgent.logger.info("instrumentAllFunc: No JS Functions to instrument.");
                return;
            }
            // Save XHR object, XHR open, XHR send
            // If window object is not found, the app will have bigger problems
            if ( window && window.XMLHttpRequest ) {
                BrowserAgent.funcUtils.saveOrigObj("XHR_ctor", window.XMLHttpRequest);
                BrowserAgent.funcUtils.saveOrigObj("XHR_ctor_open", window.XMLHttpRequest.prototype.open);
                BrowserAgent.funcUtils.saveOrigObj("XHR_ctor_send", window.XMLHttpRequest.prototype.send);
            }
            var i, funcName, pre, post;
            for ( i = 0; i < BrowserAgent.globals.functionsToInstrumentList.length; i++ ) {
                funcName = BrowserAgent.globals.functionsToInstrumentList[i].name;
                pre = BrowserAgent.globals.functionsToInstrumentList[i].pre;
                post = BrowserAgent.globals.functionsToInstrumentList[i].post;
                try {
                    // The JS function is in the scope of the window and needs to be
                    // assigned the newly generated function by BrowserAgent. The assignment at run
                    // time can be achieved by eval
                    BrowserAgent.funcUtils.assignFunc(funcName,
                                                      BrowserAgent.funcUtils.instrumentFunc(funcName,
                                                                                            pre, post,
                                                                                            BrowserAgent.globals.funcInstrumentMaxRetryCount,
                                                                                            false));
                } catch ( e ) {
                    // Do nothing. Retry is implemented in instrumentFunc
                }
            }
        },
        /**
         * Given a function name (resolvable from the window object), assigns the given function to it with Eval
         * @param funcName
         * @param b - the new function to assign to (Note: Don't change the variable name from 'b' as the compressor
         *            cannot resolve the string inside eval).
         */
        assignFunc : function ( funcName, b ) {
            if ( b ) {
                eval("window." + funcName + " = b;");
            }
        },
        /**
         * Given a object, this function saves them in BrowserAgent.globals.origFuncMap
         * @param key - an unique string
         * @param obj - JS function object or JS function to store
         */
        saveOrigObj : function ( key, obj ) {
            // TODO: This seems too loose. Tighten the check
            if ( !obj || !key ) {
                BrowserAgent.logger.warn("saveOrigObj : Cannot save original object without key or the object itself.");
                return;
            }
            BrowserAgent.globals.origFuncMap[key] = obj;
        }
    };
    /**
     * JSON Utility
     * Responsible for creating JSON objects according to the JSON schema
     */
    BrowserAgent.jsonUtils = {
        jsonConstants : {
            SCHEMA_VERSION : "2.0",
            CREATOR_NAME : "BA",
            CREATOR_VERSION : "1.0",
            APP_VERSION : "1.0"
        },
        createTT : function ( path, corBrowsGUID, browserStartTime, apmStartTime, duration, ttfb, tResponseStart,
                              apmEndTime ) {
            var tt = {}, isValid = false;
            var adjustedStartTime = browserStartTime;
            // If browser start time is way off, use the server start time as standard to adjust the TT start time
            // start time with modified Cristian's algorithm
            if ( browserStartTime > 0 && apmStartTime > 0 && ttfb > 0 && tResponseStart > 0 &&
                 ( browserStartTime > apmStartTime || (browserStartTime + duration) < apmStartTime ) ) {
                if ( !apmEndTime || isNaN(apmEndTime) || ( apmEndTime < apmStartTime ) ) {
                    apmEndTime = apmStartTime;
                }
                var serverProcTime = apmEndTime - apmStartTime;
                adjustedStartTime = browserStartTime + Math.ceil((ttfb - serverProcTime) / 2) + apmEndTime -
                                    tResponseStart;
                if ( adjustedStartTime > apmStartTime ) {
                    adjustedStartTime = apmStartTime;
                }
            }
            if ( path ) {
                tt.path = path;
                isValid = true;
            }
            if ( typeof duration === 'number' && !isNaN(duration) ) {
                tt.duration = duration;
                isValid = true;
            }
            if ( apmStartTime && corBrowsGUID ) {
                tt.correlationBrowserGUID = corBrowsGUID;
                isValid = true;
            }
            if ( typeof browserStartTime === 'number' && !isNaN(browserStartTime) ) {
                tt.startTime = browserStartTime;
                isValid = true;
            }
            if ( apmStartTime && corBrowsGUID && typeof adjustedStartTime === 'number' && !isNaN(adjustedStartTime) ) {
                tt.adjustedStartTime = adjustedStartTime;
                isValid = true;
            }
            if ( typeof BrowserAgentExtension !== 'undefined' ) {
                ////////////////////////// EXTENSION POINT [extAddCustomOptionalProperty] //////////////////////////
                BrowserAgentExtension.extAddCustomOptionalProperty();
                if ( BrowserAgentExtension.extCustomOptionalPropertyList.length > 0 ) {
                    var validatedList = [];
                    for ( var i = 0; i < BrowserAgentExtension.extCustomOptionalPropertyList.length; i++ ) {
                        var prop = BrowserAgentExtension.extCustomOptionalPropertyList[i];
                        BrowserAgent.jsonUtils.addToList(
                            BrowserAgent.jsonUtils.createXAttribute(prop.name,
                                                                    prop.value,
                                                                    prop.description),
                            validatedList);
                    }
                    if ( validatedList.length > 0 ) {
                        tt.x_attributes = { x_attributeList : validatedList };
                        isValid = true;
                    }
                    BrowserAgentExtension.extCustomOptionalPropertyList = [];
                }
            }
            return (isValid) ? tt : null;
        },
        createMetric : function ( path, name, unit, type, value ) {
            if ( !BrowserAgent.jsonUtils.validateMetric(path, name, unit, type, value) ) {
                BrowserAgent.logger.info("createMetric: Invalid metric input. Discard metric...");
                return null;
            }
            if ( typeof BrowserAgentExtension !== 'undefined' ) {
                ////////////////////////// EXTENSION POINT [extNameFormatter] //////////////////////////
                var formatted = BrowserAgentExtension.extNameFormatter(path, name, unit, type, value);
                if ( formatted ) {
                    if ( !BrowserAgent.jsonUtils.validateMetric(formatted.path, formatted.name,
                                                                formatted.unit, formatted.accumulatorType,
                                                                formatted.value) ) {
                        BrowserAgent.logger.info("createMetric: Invalid metric input after Name Formatter. Discard metric...");
                        return null;
                    }
                    path = formatted.path;
                    name = formatted.name;
                    unit = formatted.unit;
                    type = formatted.accumulatorType;
                    value = formatted.value;
                }
            }
            var metric = {
                path : path,
                name : name,
                accumulatorType : type,
                value : value
            };
            if ( type === 0 && unit ) {
                metric.unit = unit;
            }
            return metric;
        },
        validateMetric : function ( path, name, unit, type, value ) {
            if ( typeof path !== 'string' || path.length === 0 || typeof name !== 'string' || name.length === 0 ||
                 typeof type !== 'number' || typeof value !== 'number' || isNaN(value) || value < 0 ) {
                return false;
            }
            for ( var t in BrowserAgent.globals.metricAggregatorType ) {
                if ( type === BrowserAgent.globals.metricAggregatorType[t] ) {
                    return true;
                }
            }
            return false;
        },
        createBS : function ( bs, bt, btc ) {
            if ( !bs || bs === BrowserAgent.globals.UNDEFINED ) {
                return null;
            }
            return {
                name : bs,
                businessTransactionList : [
                    {
                        name : bt,
                        transactions : {
                            transactionList : [
                                {
                                    name : btc
                                }
                            ]
                        }
                    }
                ]
            };
        },
        addToList : function ( metric, metricList ) {
            if ( !metricList || !metric ) {
                return;
            }
            metricList.push(metric);
        },
        createAPMData : function ( metricList, ttList ) {
            var apmData = {};
            var isValid = false;
            if ( metricList && metricList.length > 0 ) {
                apmData.metrics = { metricList : metricList };
                isValid = true;
            }
            if ( ttList && ttList.length > 0 ) {
                apmData.transactionTraces = { transactionTraceList : ttList };
                isValid = true;
            }
            return (isValid) ? apmData : null;
        },
        createRequest : function ( url, method, bodySize ) {
            var request = {};
            var isValid = false;
            if ( typeof url === 'string' && url.length > 0 ) {
                request.url = url;
                isValid = true;
            }
            if ( typeof method === 'string' && method.length > 0 ) {
                // https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html
                // always send back the upper case of request get -> GET
                request.method = method.toUpperCase();
                isValid = true;
            }
            if ( typeof bodySize === 'number' && bodySize > 0 ) {
                request.bodySize = bodySize;
                isValid = true;
            }
            return (isValid) ? request : null;
        },
        createResponse : function ( statusCode, content ) {
            var response = {};
            var isValid = false;
            if ( typeof statusCode === 'number' ) {
                response.status = statusCode;
                isValid = true;
            }
            if ( content ) {
                response.content = content;
                isValid = true;
            }
            return (isValid) ? response : null;
        },
        createContent : function ( size ) {
            var content = {};
            var isValid = false;
            if ( typeof size === 'number' ) {
                content.size = size;
                isValid = true;
            }
            return (isValid) ? content : null;
        },
        createResource : function ( resourceType, timeStamp, bs, apmData, request, response, axaData ) {
            var resource = {};
            var isValid = false;
            if ( typeof resourceType === 'string' ) {
                resource.type = resourceType;
            }
            if ( typeof timeStamp === 'number' ) {
                resource.timeStamp = timeStamp;
            }
            if ( bs ) {
                resource.businessService = bs;
            }
            if ( apmData ) {
                resource.apmData = apmData;
                isValid = true;
            }
            if ( request ) {
                resource.request = request;
                isValid = true;
            }
            if ( response ) {
                resource.response = response;
                isValid = true;
            }
            if ( axaData ) {
                resource.axaData = axaData;
                isValid = true;
            }
            return (isValid) ? resource : null;
        },
        createError : function ( type, subType, msg, src, lineNum, colNum, stack, timeStamp, apmData, axaData ) {
            var error = {};
            var isValid = false;
            if ( type ) {
                error.type = type;
                isValid = true;
            }
            if ( subType ) {
                error.subType = subType;
                isValid = true;
            }
            if ( typeof msg === 'string' ) {
                error.message = msg;
                isValid = true;
            }
            if ( src ) {
                error.source = src;
                isValid = true;
            }
            if ( lineNum ) {
                error.lineNumber = lineNum;
                isValid = true;
            }
            if ( colNum ) {
                error.columnNumber = colNum;
                isValid = true;
            }
            if ( stack ) {
                error.stackTrace = stack;
                isValid = true;
            }
            if ( typeof timeStamp === 'number' ) {
                error.timeStamp = timeStamp;
                isValid = true;
            }
            if ( apmData ) {
                error.apmData = apmData;
                isValid = true;
            }
            if ( axaData ) {
                error.axaData = axaData;
                isValid = true;
            }
            return (isValid) ? error : null;
        },
        createXAttribute : function ( name, value, description ) {
            if ( !name || !value ) {
                return null;
            }
            var attr = {};
            attr.name = name;
            attr.value = value.toString();
            if ( description ) {
                attr.description = description;
            }
            return attr;
        },
        createCookies : function ( appCookies ) {
            if ( !appCookies ) {
                return null;
            }
            var cookieList = [], isValid = false;
            for ( var cookieName in appCookies ) {
                if ( cookieName && appCookies[cookieName] ) {
                    cookieList.push({ name : cookieName, value : appCookies[cookieName] });
                    isValid = true;
                }
            }
            if ( !isValid ) {
                return null;
            }
            return { cookieList : cookieList };
        },
        createAXAData : function ( eventList ) {
            if ( eventList && eventList.length > 0 ) {
                return { axaEventList : eventList };
            }
            return null;
        },
        createInternalData : function ( dataObj, agentCookieKeyNames ) {
            if ( !dataObj ) {
                return null;
            }
            var prefix = BrowserAgent.globals.agentCookiePrefix;
            var aggKey, internalData = {}, isValid, xattrList = [];
            for ( var name in agentCookieKeyNames ) {
                aggKey = prefix + agentCookieKeyNames[name];
                if ( dataObj[aggKey] ) {
                    internalData[aggKey] = dataObj[aggKey];
                    isValid = true;
                    delete dataObj[aggKey];
                }
            }
            for ( name in dataObj ) {
                xattrList.push(BrowserAgent.jsonUtils.createXAttribute(name, dataObj[name]));
                isValid = true;
            }
            if ( xattrList.length > 0 ) {
                internalData.x_attributes = { x_attributeList : xattrList };
            }
            return (isValid) ? internalData : null;
        },
        updateEUMWithGeo : function ( jsonObj ) {
            var customLocationStr =
                BrowserAgent.storageUtils.getFromStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                         BrowserAgent.storageUtils.storageKeys.GEOCUSTOM);

            var customLocation = null;
            if ( customLocationStr !== null ) {
                customLocation = JSON.parse(customLocationStr);
                BrowserAgent.globals.geo.lat = customLocation.lat;
                BrowserAgent.globals.geo.lon = customLocation.lon;
            }

            // Test for customLocation which indicates a custom location was found above.
            if ( !jsonObj.clientInfo.geolocation || customLocation !== null ) {
                var geo = BrowserAgent.globals.geo;
                // Don't send out of range geo-location
                if ( geo && geo.lat && geo.lon && geo.lat >= -90 && geo.lat <= 90 && geo.lon >= -180 &&
                     geo.lon <= 180 ) {
                    jsonObj.clientInfo.geolocation = {
                        latitude : geo.lat,
                        longitude : geo.lon
                    };
                }
            }
        }
    };
    /**
     * Event Utility
     * Responsible for managing Browser Agent events
     */
    BrowserAgent.evtUtils = {
        init : function () {
            // Register event handlers
            BrowserAgent.evtUtils.setEvtHndlr(BrowserAgent.globals.evtTypes.HPLOAD,
                                              BrowserAgent.evtUtils.handleHPLoadEvt);
            BrowserAgent.evtUtils.setEvtHndlr(BrowserAgent.globals.evtTypes.SPLOAD,
                                              BrowserAgent.evtUtils.handleSPLoadEvt);
            BrowserAgent.evtUtils.setEvtHndlr(BrowserAgent.globals.evtTypes.RES,
                                              BrowserAgent.evtUtils.handleResEvt);
            BrowserAgent.evtUtils.setEvtHndlr(BrowserAgent.globals.evtTypes.JSERR,
                                              BrowserAgent.evtUtils.handleJSErrEvt);
            BrowserAgent.evtUtils.setEvtHndlr(BrowserAgent.globals.evtTypes.FN,
                                              BrowserAgent.evtUtils.handleFnEvt);
            BrowserAgent.evtUtils.setEvtHndlr(BrowserAgent.globals.evtTypes.APMEXT,
                                              BrowserAgent.evtUtils.handleAPMExtEvt);
            BrowserAgent.evtUtils.setEvtHndlr(BrowserAgent.globals.evtTypes.AXAEXT,
                                              BrowserAgent.evtUtils.handleAXAExtEvt);
            BrowserAgent.evtUtils.setEvtHndlr(BrowserAgent.globals.evtTypes.TTIME,
                                              BrowserAgent.evtUtils.handleTTimeEvt);
        },
        /**
         * Determines if a resource event is valid or not based on the available data inside its event object
         * @param evtObj
         * @returns {boolean}
         */
        isValidResEvt : function ( evtObj ) {
            if ( !evtObj ) {
                return false;
            }
            // Check the minimum set of fields inside the resource event object
            var isMinValid = false;
            if ( evtObj[BrowserAgent.globals.timestampNames.END_TIME] &&
                 evtObj[BrowserAgent.globals.ajaxDataKeys.URL] &&
                 evtObj[BrowserAgent.globals.timestampNames.CALLBACK_END_TIME] ) {
                isMinValid = true;
            }
            if ( BrowserAgent.globals.isJQOne ) {
                return isMinValid;
            }
            if ( isMinValid && evtObj[BrowserAgent.globals.timestampNames.LAST_BYTE] &&
                 evtObj[BrowserAgent.globals.timestampNames.FIRST_BYTE] ) {
                return true;
            }
            return false;
        },
        /**
         * Obtains a reference to an event object in the current page bucket's evtMap
         * @param evtType
         * @param isClone
         * @param startTimeKey
         * @returns {*}
         */
        getEvtObject : function ( evtType, isClone, startTimeKey ) {
            var now = Date.now();
            if ( BrowserAgent.globals.currPagePtr.isExcluded ) {
                return null;
            }
            var id = BrowserAgent.globals.getSequenceNum();
            // If new session need to be created, then create a new page bucket
            if ( !BrowserAgent.browserUtils.isSameSession(now) ) {
                BrowserAgent.pageUtils.addNewPageBucket(BrowserAgent.globals.currPagePtr.json.pageType,
                                                        BrowserAgent.globals.currPagePtr.json.url, now, false,
                                                        BrowserAgent.browserUtils.cloneTrackerData());
            } else {
                // Update last event timeStamp
                BrowserAgent.storageUtils.putInStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                       BrowserAgent.storageUtils.storageKeys.BALASTEVENT_TIME,
                                                       now, true);
            }
            BrowserAgent.globals.currPagePtr.evtMap[id] = { id : id, type : evtType };
            BrowserAgent.globals.currPagePtr.evtCount += 1;
            BrowserAgent.globals.pageWithEventsMap[BrowserAgent.globals.currPagePtr.id] = 1;
            // Clone the tracker data
            if ( isClone ) {
                BrowserAgent.globals.currPagePtr.evtMap[id][BrowserAgent.globals.trackerDataKey] =
                    BrowserAgent.browserUtils.cloneTrackerData();
            }
            // If start time key is provided, mark down the start time of the event in the evt object
            if ( startTimeKey ) {
                BrowserAgent.globals.currPagePtr.evtMap[id][startTimeKey] = now;
            }
            return BrowserAgent.globals.currPagePtr.evtMap[id];
        },
        /**
         * Registers an event handler for the given event type
         * @param evtType
         * @param hndlr
         */
        setEvtHndlr : function ( evtType, hndlr ) {
            if ( !BrowserAgent.globals.evtTypes[evtType] || typeof hndlr !== 'function' ) {
                BrowserAgent.logger.warn("setEvtHndlr: Cannot set event handler for event type [" + evtType + "]");
                return;
            }
            BrowserAgent.globals.evtHandlers[evtType] = hndlr;
        },
        /**
         * Event Handler for HPLoad event
         * @param metricPath
         * @param jsonObj
         * @param dataObj
         * @returns {boolean}
         */
        handleHPLoadEvt : function ( metricPath, jsonObj, dataObj ) {
            if ( !dataObj ) {
                return false;
            }
            if ( !metricPath || !jsonObj || !BrowserAgent.globals.configs.PAGELOADMETRICSENABLED ) {
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            // Since pageLoadMetrics are enabled and we got a page load event, mark it as a new page
            jsonObj.pageLoadFlag = true;
            if ( !dataObj.raw ) {
                // Mark for deletion
                dataObj.isDelete = true;
                BrowserAgent.logger.warn("handleHPLoadEvt: Obtained invalid page load data point. Deleting it...");
                return false;
            }
            var PLT = dataObj.raw.loadEventEnd - dataObj.raw.navigationStart;
            // Below threshold
            if ( PLT > 0 && PLT < BrowserAgent.globals.configs.PAGELOADMETRICSTHRESHOLD ) {
                BrowserAgent.logger.info("handleHPLoadEvt: Skipping harvest of Page metrics for as it is below the configured Page metric threshold (" +
                                         BrowserAgent.globals.configs.PAGELOADMETRICSTHRESHOLD + " ms)");
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            // URL metric context is DISABLED
            if ( !jsonObj.businessService && BrowserAgent.globals.configs.URLMETRICOFF ) {
                BrowserAgent.logger.info("handleHPLoadEvt: Skipping harvest of Page metrics as URL metric context is DISABLED");
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            // If initial url has hash, set page load metrics path to pageMetricPathNoHash
            var metricPathWithHash = null;
            if ( BrowserAgent.globals.initPageInfo.pageMetricPathNoHash ) {
                metricPathWithHash = metricPath;
                metricPath = BrowserAgent.globals.initPageInfo.pageMetricPathNoHash;
            }
            // Create Metrics
            var TTFB = dataObj.raw.responseStart - dataObj.raw.requestStart;
            var metricList = [];
            BrowserAgent.jsonUtils.addToList(BrowserAgent.jsonUtils.createMetric(metricPath,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_PRT.name,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_PRT.unit,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_PRT.type,
                                                                                 dataObj.raw.loadEventEnd -
                                                                                 dataObj.raw.domComplete), metricList);
            BrowserAgent.jsonUtils.addToList(BrowserAgent.jsonUtils.createMetric(metricPath,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_CET.name,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_CET.unit,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_CET.type,
                                                                                 dataObj.raw.connectEnd -
                                                                                 dataObj.raw.connectStart), metricList);
            BrowserAgent.jsonUtils.addToList(BrowserAgent.jsonUtils.createMetric(metricPath,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_DLT.name,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_DLT.unit,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_DLT.type,
                                                                                 dataObj.raw.domainLookupEnd -
                                                                                 dataObj.raw.domainLookupStart),
                                             metricList);
            BrowserAgent.jsonUtils.addToList(BrowserAgent.jsonUtils.createMetric(metricPath,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_DPT.name,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_DPT.unit,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_DPT.type,
                                                                                 dataObj.raw.domComplete -
                                                                                 dataObj.raw.domLoading), metricList);
            BrowserAgent.jsonUtils.addToList(BrowserAgent.jsonUtils.createMetric(metricPath,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_PLT.name,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_PLT.unit,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_PLT.type,
                                                                                 PLT), metricList);
            BrowserAgent.jsonUtils.addToList(BrowserAgent.jsonUtils.createMetric(metricPath,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_PST.name,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_PST.unit,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_PST.type,
                                                                                 dataObj.raw.connectStart -
                                                                                 dataObj.raw.domainLookupEnd +
                                                                                 dataObj.raw.requestStart -
                                                                                 dataObj.raw.connectEnd), metricList);
            BrowserAgent.jsonUtils.addToList(BrowserAgent.jsonUtils.createMetric(metricPath,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_PPUT.name,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_PPUT.unit,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_PPUT.type,
                                                                                 dataObj.raw.unloadEventEnd -
                                                                                 dataObj.raw.unloadEventStart),
                                             metricList);
            BrowserAgent.jsonUtils.addToList(BrowserAgent.jsonUtils.createMetric(metricPath,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_TTFB.name,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_TTFB.unit,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_TTFB.type,
                                                                                 TTFB), metricList);
            BrowserAgent.jsonUtils.addToList(BrowserAgent.jsonUtils.createMetric(metricPath,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_TTLB.name,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_TTLB.unit,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_TTLB.type,
                                                                                 dataObj.raw.responseEnd -
                                                                                 dataObj.raw.requestStart), metricList);
            BrowserAgent.jsonUtils.addToList(BrowserAgent.jsonUtils.createMetric(metricPath,
                                                                                 BrowserAgent.globals.defaultMetricDefs.PAGE_HPI.name,
                                                                                 BrowserAgent.globals.defaultMetricDefs.PAGE_HPI.unit,
                                                                                 BrowserAgent.globals.defaultMetricDefs.PAGE_HPI.type,
                                                                                 1), metricList);
            // If initial url has hash, report Page Load Time and Page Hits Per Interval under metric path with hash
            if ( metricPathWithHash ) {
                BrowserAgent.jsonUtils.addToList(BrowserAgent.jsonUtils.createMetric(metricPathWithHash,
                                                                                     BrowserAgent.globals.defaultMetricDefs.NTAPI_PLT.name,
                                                                                     BrowserAgent.globals.defaultMetricDefs.NTAPI_PLT.unit,
                                                                                     BrowserAgent.globals.defaultMetricDefs.NTAPI_PLT.type,
                                                                                     PLT), metricList);
                BrowserAgent.jsonUtils.addToList(BrowserAgent.jsonUtils.createMetric(metricPathWithHash,
                                                                                     BrowserAgent.globals.defaultMetricDefs.PAGE_HPI.name,
                                                                                     BrowserAgent.globals.defaultMetricDefs.PAGE_HPI.unit,
                                                                                     BrowserAgent.globals.defaultMetricDefs.PAGE_HPI.type,
                                                                                     1), metricList);
            }

            if ( typeof BrowserAgentExtension !== 'undefined' ) {
                ///////////////////// EXTENSION POINT [extAddCustomPageMetric] ////////////////////
                BrowserAgentExtension.extAddCustomPageMetric();
                if ( BrowserAgentExtension.extCustomPageMetricList.length > 0 ) {
                    for ( var i = 0; i < BrowserAgentExtension.extCustomPageMetricList.length; i++ ) {
                        var extMetric = BrowserAgentExtension.extCustomPageMetricList[i];
                        BrowserAgent.jsonUtils.addToList(BrowserAgent.jsonUtils.createMetric(metricPath,
                                                                                             extMetric.name,
                                                                                             extMetric.unit,
                                                                                             extMetric.accumulatorType,
                                                                                             extMetric.value),
                                                         metricList);
                    }
                    BrowserAgentExtension.extCustomPageMetricList = [];
                }
            }
            // Create TT
            // if there are metrics then TT path will be the metric path of the first metric in the list,
            // otherwise it will use the original metric path before name formatter
            var ttPath = (metricList.length > 0) ? metricList[0].path : metricPath;
            var ttList = [];
            BrowserAgent.jsonUtils.addToList(BrowserAgent.jsonUtils.createTT(ttPath,
                                                                             BrowserAgent.globals.CorBrowsGUID,
                                                                             dataObj.raw.navigationStart,
                                                                             parseInt(BrowserAgent.globals.startTime),
                                                                             PLT,
                                                                             TTFB,
                                                                             dataObj.raw.responseStart,
                                                                             parseInt(BrowserAgent.globals.endTime)),
                                             ttList);
            // Create final JSON
            var isValid = false;
            var apmData = BrowserAgent.jsonUtils.createAPMData(metricList, ttList);
            var axaData = BrowserAgent.jsonUtils.createAXAData(dataObj[BrowserAgent.globals.trackerDataKey]);
            jsonObj.rawData = { navigationTiming : BrowserAgent.browserUtils.copyObj(dataObj.raw) };
            // attach Agent cookies
            if ( BrowserAgent.globals.agentCookies ) {

                var internalData = BrowserAgent.jsonUtils.createInternalData(BrowserAgent.globals.agentCookies,
                                                                             BrowserAgent.globals.agentCookieKeyName);
                if ( internalData ) {
                    jsonObj.internalData = internalData;
                }
            }
            if ( apmData ) {
                jsonObj.apmData = apmData;
                isValid = true;
            }
            if ( axaData ) {
                jsonObj.axaData = axaData;
                isValid = true;
            }
            return isValid;
        },
        /**
         * Event Handler for SPLoad event
         * @param metricPath
         * @param jsonObj
         * @param dataObj
         * @returns {boolean}
         */
        handleSPLoadEvt : function ( metricPath, jsonObj, dataObj ) {
            if ( !dataObj ) {
                return false;
            }
            if ( !metricPath || !jsonObj || !BrowserAgent.globals.configs.PAGELOADMETRICSENABLED ) {
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            // Since pageLoadMetrics are enabled and we got a page load event, mark it as a new page
            jsonObj.pageLoadFlag = true;
            if ( !dataObj[BrowserAgent.globals.softPageDataKeys.START] ||
                 !dataObj[BrowserAgent.globals.softPageDataKeys.END] ) {
                // Mark for deletion
                dataObj.isDelete = true;
                BrowserAgent.logger.warn("handleSPLoadEvt: Obtained invalid page load data point. Deleting it...");
                return false;
            }
            var PLT = dataObj[BrowserAgent.globals.softPageDataKeys.END] -
                      dataObj[BrowserAgent.globals.softPageDataKeys.START];
            // Below threshold
            if ( PLT > 0 && PLT < BrowserAgent.globals.configs.PAGELOADMETRICSTHRESHOLD ) {
                BrowserAgent.logger.info("handleSPLoadEvt: Skipping harvest of Soft Page metrics for as it is below the configured Page metric threshold (" +
                                         BrowserAgent.globals.configs.PAGELOADMETRICSTHRESHOLD + " ms)");
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            // URL metric context is DISABLED
            if ( !jsonObj.businessService && BrowserAgent.globals.configs.URLMETRICOFF ) {
                BrowserAgent.logger.info("handleSPLoadEvt: Skipping harvest of Page metrics as URL metric context is DISABLED");
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            var metricList = [];
            BrowserAgent.jsonUtils.addToList(BrowserAgent.jsonUtils.createMetric(metricPath,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_PLT.name,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_PLT.unit,
                                                                                 BrowserAgent.globals.defaultMetricDefs.NTAPI_PLT.type,
                                                                                 PLT), metricList);
            BrowserAgent.jsonUtils.addToList(BrowserAgent.jsonUtils.createMetric(metricPath,
                                                                                 BrowserAgent.globals.defaultMetricDefs.PAGE_HPI.name,
                                                                                 BrowserAgent.globals.defaultMetricDefs.PAGE_HPI.unit,
                                                                                 BrowserAgent.globals.defaultMetricDefs.PAGE_HPI.type,
                                                                                 1), metricList);
            // Create final JSON
            var isValid = false;
            var apmData = BrowserAgent.jsonUtils.createAPMData(metricList, null);
            var axaData = BrowserAgent.jsonUtils.createAXAData(dataObj[BrowserAgent.globals.trackerDataKey]);
            jsonObj.rawData = {
                softPageTiming : {
                    startTime : dataObj[BrowserAgent.globals.softPageDataKeys.START],
                    endTime : dataObj[BrowserAgent.globals.softPageDataKeys.END]
                }
            };
            if ( apmData ) {
                jsonObj.apmData = apmData;
                isValid = true;
            }
            if ( axaData ) {
                jsonObj.axaData = axaData;
                isValid = true;
            }
            return isValid;
        },
        /**
         * Event Handler for Res event
         * @param metricPath
         * @param jsonObj
         * @param dataObj
         * @returns {boolean}
         */
        handleResEvt : function ( metricPath, jsonObj, dataObj ) {
            if ( !dataObj ) {
                return false;
            }
            if ( !metricPath || !jsonObj || !BrowserAgent.evtUtils.isValidResEvt(dataObj) ||
                 !BrowserAgent.globals.configs.AJAXMETRICSENABLED ) {
                BrowserAgent.logger.warn("handleResEvt: Obtained invalid AJAX data point or AJAX metrics disabled. Deleting it...");
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            // Below threshold
            var RLT = dataObj[BrowserAgent.globals.timestampNames.CALLBACK_END_TIME] -
                      dataObj[BrowserAgent.globals.timestampNames.END_TIME];
            if ( RLT > 0 && RLT < BrowserAgent.globals.configs.AJAXMETRICSTHRESHOLD ) {
                BrowserAgent.logger.info("handleResEvt: Skipping harvest of resource metrics for " +
                                         dataObj[BrowserAgent.globals.ajaxDataKeys.URL] +
                                         " as it is below the configured resource metric threshold");
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            // Check if ajax data point has ajax BT info
            var hasAjaxBT = (dataObj[BrowserAgent.cookieUtils.cookieKeys.bsChar] &&
                             dataObj[BrowserAgent.cookieUtils.cookieKeys.bsChar] !==
                             BrowserAgent.globals.UNDEFINED);
            // If bs is not defined, then the data point is in URL context. Check if the
            // URL metrics are on. If not, skip the rest of the logic
            if ( (!hasAjaxBT) && (!jsonObj.businessService) && BrowserAgent.globals.configs.URLMETRICOFF ) {
                BrowserAgent.logger.info("handleResEvt: Skipping harvest of AJAX metrics as NON-BT based metrics are OFF");
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            if ( hasAjaxBT ) {
                metricPath = BrowserAgent.globals.metricPathConsts.PREFIX + BrowserAgent.globals.pipeChar +
                             dataObj[BrowserAgent.cookieUtils.cookieKeys.bsChar] +
                             BrowserAgent.globals.pipeChar +
                             dataObj[BrowserAgent.cookieUtils.cookieKeys.btChar] +
                             BrowserAgent.globals.pipeChar +
                             dataObj[BrowserAgent.cookieUtils.cookieKeys.btcChar] +
                             BrowserAgent.globals.pipeChar + BrowserAgent.globals.metricPathConsts.BROWSER;
            }
            var BS = BrowserAgent.jsonUtils.createBS(dataObj[BrowserAgent.cookieUtils.cookieKeys.bsChar],
                                                     dataObj[BrowserAgent.cookieUtils.cookieKeys.btChar],
                                                     dataObj[BrowserAgent.cookieUtils.cookieKeys.btcChar]);
            var parser = BrowserAgent.browserUtils.parseURL(dataObj[BrowserAgent.globals.ajaxDataKeys.URL]);
            var resURL = parser.hostname + BrowserAgent.globals.forwardSlashChar + parser.port +
                         BrowserAgent.globals.pipeChar + parser.pathname;
            var TTFB = dataObj[BrowserAgent.globals.timestampNames.FIRST_BYTE] -
                       dataObj[BrowserAgent.globals.timestampNames.END_TIME];
            var RDT = dataObj[BrowserAgent.globals.timestampNames.LAST_BYTE] -
                      dataObj[BrowserAgent.globals.timestampNames.FIRST_BYTE];
            metricPath += BrowserAgent.globals.pipeChar + BrowserAgent.globals.metricPathConsts.AJAX +
                          BrowserAgent.globals.pipeChar + resURL;
            var metricList = [];
            BrowserAgent.jsonUtils.addToList(
                BrowserAgent.jsonUtils.createMetric(metricPath,
                                                    BrowserAgent.globals.defaultMetricDefs.AJAX_RLT.name,
                                                    BrowserAgent.globals.defaultMetricDefs.AJAX_RLT.unit,
                                                    BrowserAgent.globals.defaultMetricDefs.AJAX_RLT.type,
                                                    RLT), metricList);
            if ( TTFB >= 0 ) {
                BrowserAgent.jsonUtils.addToList(
                    BrowserAgent.jsonUtils.createMetric(metricPath,
                                                        BrowserAgent.globals.defaultMetricDefs.AJAX_TTFB.name,
                                                        BrowserAgent.globals.defaultMetricDefs.AJAX_TTFB.unit,
                                                        BrowserAgent.globals.defaultMetricDefs.AJAX_TTFB.type, TTFB),
                    metricList);
            }
            if ( RDT >= 0 ) {
                BrowserAgent.jsonUtils.addToList(
                    BrowserAgent.jsonUtils.createMetric(metricPath,
                                                        BrowserAgent.globals.defaultMetricDefs.AJAX_RDT.name,
                                                        BrowserAgent.globals.defaultMetricDefs.AJAX_RDT.unit,
                                                        BrowserAgent.globals.defaultMetricDefs.AJAX_RDT.type, RDT),
                    metricList);
            }
            BrowserAgent.jsonUtils.addToList(
                BrowserAgent.jsonUtils.createMetric(metricPath,
                                                    BrowserAgent.globals.defaultMetricDefs.AJAX_CBET.name,
                                                    BrowserAgent.globals.defaultMetricDefs.AJAX_CBET.unit,
                                                    BrowserAgent.globals.defaultMetricDefs.AJAX_CBET.type,
                                                    dataObj[BrowserAgent.globals.timestampNames.CALLBACK_END_TIME] -
                                                    dataObj[BrowserAgent.globals.timestampNames.CALLBACK_START_TIME]),
                metricList);
            BrowserAgent.jsonUtils.addToList(
                BrowserAgent.jsonUtils.createMetric(metricPath,
                                                    BrowserAgent.globals.defaultMetricDefs.AJAX_ICPI.name,
                                                    BrowserAgent.globals.defaultMetricDefs.AJAX_ICPI.unit,
                                                    BrowserAgent.globals.defaultMetricDefs.AJAX_ICPI.type, 1),
                metricList);
            if ( typeof BrowserAgentExtension !== 'undefined' ) {
                ////////////////////////// EXTENSION POINT [extAddCustomAjaxMetric] //////////////////////////
                BrowserAgentExtension.extAddCustomAjaxMetric();
                if ( BrowserAgentExtension.extCustomAjaxMetricList.length > 0 ) {
                    for ( var i = 0; i < BrowserAgentExtension.extCustomAjaxMetricList.length; i++ ) {
                        var extMetric = BrowserAgentExtension.extCustomAjaxMetricList[i];
                        BrowserAgent.jsonUtils.addToList(BrowserAgent.jsonUtils.createMetric(metricPath,
                                                                                             extMetric.name,
                                                                                             extMetric.unit,
                                                                                             extMetric.accumulatorType,
                                                                                             extMetric.value),
                                                         metricList);

                    }
                    BrowserAgentExtension.extCustomAjaxMetricList = [];
                }
            }
            // If there are metrics then TT path will be the metric path of the first metric in the
            // list, otherwise it will use the original metric path before name formatter
            var ttPath = (metricList.length > 0) ? metricList[0].path : metricPath;
            var ttList = [];
            BrowserAgent.jsonUtils.addToList(BrowserAgent.jsonUtils.createTT(ttPath,
                                                                             dataObj[BrowserAgent.cookieUtils.cookieKeys.CorBrowsGUIDChar],
                                                                             dataObj[BrowserAgent.globals.timestampNames.END_TIME],
                                                                             parseInt(dataObj[BrowserAgent.cookieUtils.cookieKeys.apmStartTimeChar]),
                                                                             RLT,
                                                                             TTFB,
                                                                             dataObj[BrowserAgent.globals.timestampNames.FIRST_BYTE],
                                                                             parseInt(dataObj[BrowserAgent.cookieUtils.cookieKeys.apmEndTimeChar])),
                                             ttList);

            // Create Final JSON
            var resource = BrowserAgent.jsonUtils.createResource(BrowserAgent.globals.resourceType.AJAX,
                                                                 dataObj[BrowserAgent.globals.timestampNames.END_TIME],
                                                                 BS,
                                                                 BrowserAgent.jsonUtils.createAPMData(metricList,
                                                                                                      ttList),
                                                                 BrowserAgent.jsonUtils.createRequest(dataObj[BrowserAgent.globals.ajaxDataKeys.URL],
                                                                                                      dataObj[BrowserAgent.globals.ajaxDataKeys.METHOD],
                                                                                                      dataObj[BrowserAgent.globals.ajaxDataKeys.REQUEST_BODY_SIZE]),
                                                                 BrowserAgent.jsonUtils.createResponse(dataObj[BrowserAgent.globals.ajaxDataKeys.STATUS_CODE],
                                                                                                       BrowserAgent.jsonUtils.createContent(dataObj[BrowserAgent.globals.ajaxDataKeys.RESPONSE_CONTENT_LENGTH])),
                                                                 BrowserAgent.jsonUtils.createAXAData(dataObj[BrowserAgent.globals.trackerDataKey]));

            var key = BrowserAgent.globals.agentCookieKeys;
            if ( dataObj[key] ) {
                var internalData = BrowserAgent.jsonUtils.createInternalData(dataObj[key],
                                                                             BrowserAgent.globals.agentCookieKeyName);
                if ( internalData ) {
                    resource.internalData = internalData;
                }
            }
            if ( resource ) {
                if ( !jsonObj.resources ) {
                    jsonObj.resources = { resourceList : [] };
                }
                jsonObj.resources.resourceList.push(resource);
                return true;
            }
            return false;
        },
        /**
         * Event Handler for JSErr event
         * @param metricPath
         * @param jsonObj
         * @param dataObj
         * @returns {boolean}
         */
        handleJSErrEvt : function ( metricPath, jsonObj, dataObj ) {
            if ( !dataObj ) {
                return false;
            }
            if ( !metricPath || !jsonObj || !BrowserAgent.globals.configs.JSERRORSENABLED ) {
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            if ( typeof dataObj[BrowserAgent.errorUtils.errorDataFields.MSG] !== 'string' ||
                 typeof dataObj[BrowserAgent.errorUtils.errorDataFields.STT] !== 'number' ) {
                BrowserAgent.logger.info("handleJSErrEvt: Obtained an invalid JS error data point. Deleting it...");
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            // URL metric context is DISABLED
            if ( !jsonObj.businessService && BrowserAgent.globals.configs.URLMETRICOFF ) {
                BrowserAgent.logger.info("handleJSErrEvt: Skipping harvest of JS error metrics as NON-BT based metrics are OFF");
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            // Create Final JSON
            var err = {
                timeStamp : dataObj[BrowserAgent.errorUtils.errorDataFields.STT],
                message : dataObj[BrowserAgent.errorUtils.errorDataFields.MSG]
            };
            var ECPI = BrowserAgent.jsonUtils.createMetric(metricPath,
                                                           BrowserAgent.globals.defaultMetricDefs.JSERR_CPI.name,
                                                           BrowserAgent.globals.defaultMetricDefs.JSERR_CPI.unit,
                                                           BrowserAgent.globals.defaultMetricDefs.JSERR_CPI.type,
                                                           1);
            if ( ECPI ) {
                var apmData = BrowserAgent.jsonUtils.createAPMData([ECPI], null);
                if ( apmData ) {
                    err.apmData = apmData;
                }
            }
            var axaData = BrowserAgent.jsonUtils.createAXAData(dataObj[BrowserAgent.globals.trackerDataKey]);
            if ( axaData ) {
                err.axaData = axaData;
            }
            if ( dataObj[BrowserAgent.errorUtils.errorDataFields.TYP] ) {
                err.type = dataObj[BrowserAgent.errorUtils.errorDataFields.TYP];
            }
            if ( dataObj[BrowserAgent.errorUtils.errorDataFields.SUB] ) {
                err.subType = dataObj[BrowserAgent.errorUtils.errorDataFields.SUB];
            }
            if ( dataObj[BrowserAgent.errorUtils.errorDataFields.SRC] ) {
                err.source = dataObj[BrowserAgent.errorUtils.errorDataFields.SRC];
            }
            if ( dataObj[BrowserAgent.errorUtils.errorDataFields.LIN] ) {
                err.lineNumber = dataObj[BrowserAgent.errorUtils.errorDataFields.LIN];
            }
            if ( dataObj[BrowserAgent.errorUtils.errorDataFields.COL] ) {
                err.columnNumber = dataObj[BrowserAgent.errorUtils.errorDataFields.COL];
            }
            if ( dataObj[BrowserAgent.errorUtils.errorDataFields.STK] ) {
                err.stackTrace = dataObj[BrowserAgent.errorUtils.errorDataFields.STK];
            }
            if ( err ) {
                if ( !jsonObj.errors ) {
                    jsonObj.errors = { errorList : [] };
                }
                jsonObj.errors.errorList.push(err);
                return true;
            }
            return false;
        },
        /**
         * Event Handler for FN event
         * @param metricPath
         * @param jsonObj
         * @param dataObj
         * @returns {boolean}
         */
        handleFnEvt : function ( metricPath, jsonObj, dataObj ) {
            if ( !dataObj ) {
                return false;
            }
            if ( !metricPath || !jsonObj || !BrowserAgent.globals.configs.JSFUNCTIONMETRICSENABLED ) {
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            if ( !dataObj[BrowserAgent.globals.timestampNames.START_TIME] ||
                 !dataObj[BrowserAgent.globals.timestampNames.END_TIME] || !dataObj.fnName ) {
                BrowserAgent.logger.warn("handleFnEvt: Obtained invalid JS Function data point. Deleting it...");
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            // URL metric context is DISABLED
            if ( !jsonObj.businessService && BrowserAgent.globals.configs.URLMETRICOFF ) {
                BrowserAgent.logger.info("handleFnEvt: Skipping harvest of JS Function metrics as NON-BT based metrics are OFF");
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            var ET = dataObj[BrowserAgent.globals.timestampNames.END_TIME] -
                     dataObj[BrowserAgent.globals.timestampNames.START_TIME];
            if ( ET > 0 && ET < BrowserAgent.globals.configs.JSFUNCTIONMETRICSTHRESHOLD ) {
                BrowserAgent.logger.info("handleFnEvt: Skipping harvest of JS function metrics for " +
                                         dataObj.fnName +
                                         " as it is below the configured JS Function metric threshold");
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            metricPath += BrowserAgent.globals.pipeChar + BrowserAgent.globals.metricPathConsts.FUNC +
                          BrowserAgent.globals.pipeChar + dataObj.fnName;
            var metricList = [];
            metricList.push(BrowserAgent.jsonUtils.createMetric(metricPath,
                                                                BrowserAgent.globals.defaultMetricDefs.FUNC_ET.name,
                                                                BrowserAgent.globals.defaultMetricDefs.FUNC_ET.unit,
                                                                BrowserAgent.globals.defaultMetricDefs.FUNC_ET.type,
                                                                ET));
            metricList.push(BrowserAgent.jsonUtils.createMetric(metricPath,
                                                                BrowserAgent.globals.defaultMetricDefs.FUNC_ICPI.name,
                                                                BrowserAgent.globals.defaultMetricDefs.FUNC_ICPI.unit,
                                                                BrowserAgent.globals.defaultMetricDefs.FUNC_ICPI.type,
                                                                1));
            if ( typeof BrowserAgentExtension !== 'undefined' ) {
                ///////////////////// EXTENSION POINT [extAddCustomJSFuncMetric] ////////////////////
                BrowserAgentExtension.extAddCustomJSFuncMetric();
                if ( BrowserAgentExtension.extCustomJSFuncMetricList.length > 0 ) {
                    for ( var j = 0; j < BrowserAgentExtension.extCustomJSFuncMetricList.length; j++ ) {
                        var extMetric = BrowserAgentExtension.extCustomJSFuncMetricList[j];
                        BrowserAgent.jsonUtils.addToList(BrowserAgent.jsonUtils.createMetric(metricPath,
                                                                                             extMetric.name,
                                                                                             extMetric.unit,
                                                                                             extMetric.accumulatorType,
                                                                                             extMetric.value),
                                                         metricList);

                    }
                    BrowserAgentExtension.extCustomJSFuncMetricList = [];
                }
            }

            var apmData = BrowserAgent.jsonUtils.createAPMData(metricList, null);
            if ( !apmData ) {
                return false;
            }
            var cEvt = {
                timeStamp : dataObj[BrowserAgent.globals.timestampNames.START_TIME],
                apmData : apmData
            };
            var axaData = BrowserAgent.jsonUtils.createAXAData(dataObj[BrowserAgent.globals.trackerDataKey]);
            if ( axaData ) {
                cEvt.axaData = axaData;
            }
            if ( cEvt ) {
                if ( !jsonObj.clientEvents ) {
                    jsonObj.clientEvents = { clientEventList : [] };
                }
                jsonObj.clientEvents.clientEventList.push(cEvt);
                return true;
            }
            return false;
        },
        /**
         * Event Handler for APMEXT event
         * @param metricPath
         * @param jsonObj
         * @param dataObj
         * @returns {boolean}
         */
        handleAPMExtEvt : function ( metricPath, jsonObj, dataObj ) {
            if ( !dataObj ) {
                return false;
            }
            if ( !metricPath || !jsonObj || !BrowserAgent.globals.configs.BROWSERAGENTENABLED ) {
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            if ( !dataObj.lst || dataObj.lst.length < 1 ) {
                BrowserAgent.logger.info("handleAPMExtEvt: Obtained invalid APM extension metrics list. Deleting it...");
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            // URL metric context is DISABLED
            if ( !jsonObj.businessService && BrowserAgent.globals.configs.URLMETRICOFF ) {
                BrowserAgent.logger.info("handleAPMExtEvt: Skipping harvest of APM extension metrics as NON-BT based metrics are OFF");
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            var apmData = BrowserAgent.jsonUtils.createAPMData(dataObj.lst, null);
            if ( !apmData ) {
                return false;
            }
            var extEvt = { apmData : apmData };
            if ( extEvt ) {
                if ( !jsonObj.extensions ) {
                    jsonObj.extensions = { extensionList : [] };
                }
                jsonObj.extensions.extensionList.push(extEvt);
                return true;
            }
            return false;
        },
        /**
         * Event Handler for AXAEXT event
         * @param metricPath
         * @param jsonObj
         * @param dataObj
         * @returns {boolean}
         */
        handleAXAExtEvt : function ( metricPath, jsonObj, dataObj ) {
            if ( !dataObj ) {
                return false;
            }
            if ( !metricPath || !jsonObj || !BrowserAgent.globals.configs.BROWSERAGENTENABLED ) {
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            if ( !dataObj.d || dataObj.d.length < 1 ) {
                BrowserAgent.logger.info("handleAXAExtEvt: Obtained invalid AXA extension data. Deleting it...");
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            if ( !jsonObj.axaData ) {
                jsonObj.axaData = { axaEventList : [] };
            }
            jsonObj.axaData.axaEventList.push(dataObj.d);
            return true;
        },
        /**
         * Event Handler for TTime event
         * @param metricPath
         * @param jsonObj
         * @param dataObj
         * @returns {boolean}
         */
        handleTTimeEvt : function ( metricPath, jsonObj, dataObj ) {
            if ( !dataObj ) {
                return false;
            }
            if ( !metricPath || !jsonObj || !BrowserAgent.globals.configs.BROWSERAGENTENABLED ) {
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            if ( !dataObj.s || !dataObj.e || dataObj.e < dataObj.s ) {
                BrowserAgent.logger.info("handleTTimeEvt: Obtained invalid think time data. Deleting it...");
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            // URL metric context is DISABLED
            if ( !jsonObj.businessService && BrowserAgent.globals.configs.URLMETRICOFF ) {
                BrowserAgent.logger.info("handleTTimeEvt: Skipping harvest of think time metric(s) as NON-BT based metrics are OFF");
                // Mark for deletion
                dataObj.isDelete = true;
                return false;
            }
            var UDT = BrowserAgent.jsonUtils.createMetric(metricPath,
                                                          BrowserAgent.globals.defaultMetricDefs.PAGE_UDT.name,
                                                          BrowserAgent.globals.defaultMetricDefs.PAGE_UDT.unit,
                                                          BrowserAgent.globals.defaultMetricDefs.PAGE_UDT.type,
                                                          dataObj.e - dataObj.s);
            if ( !UDT ) {
                return false;
            }
            var apmData = BrowserAgent.jsonUtils.createAPMData([UDT], null);
            if ( !apmData ) {
                return false;
            }
            var ttEvt = {
                desc : "pageThinkTime",
                startTime : dataObj.s,
                endTime : dataObj.e,
                apmData : apmData
            };
            var axaData = BrowserAgent.jsonUtils.createAXAData(dataObj[BrowserAgent.globals.trackerDataKey]);
            if ( axaData ) {
                ttEvt.axaData = axaData;
            }
            if ( ttEvt ) {
                if ( !jsonObj.thinkTimes ) {
                    jsonObj.thinkTimes = { thinkTimeList : [] };
                }
                jsonObj.thinkTimes.thinkTimeList.push(ttEvt);
                return true;
            }
            return false;
        },
        /**
         * Harvest Function that reaps all events that are ready to be dispatched
         */
        harvestEvts : function () {
            var pgId, pg, evt, pgJSON, isPgReady, pgList = [], eum;
            // Loop through the pageWithEventsMap
            for ( pgId in BrowserAgent.globals.pageWithEventsMap ) {
                isPgReady = false;
                // Get the page reference from pageBuckets
                pg = BrowserAgent.globals.pageBucketsMap[pgId];
                pgJSON = JSON.parse(JSON.stringify(pg.json));
                // Loop through this page's evtMap
                for ( evt in pg.evtMap ) {
                    // Delete marked evts
                    if ( pg.evtMap[evt].isDelete ) {
                        delete pg.evtMap[evt];
                        pg.evtCount -= 1;
                        continue;
                    }
                    if ( !pg.evtMap[evt].isDone ) {
                        continue;
                    }
                    isPgReady = BrowserAgent.globals.evtHandlers[pg.evtMap[evt].type](pg.pageMetricPath, pgJSON,
                                                                                      pg.evtMap[evt]) || isPgReady;
                    // Delete the event
                    delete pg.evtMap[evt];
                    pg.evtCount -= 1;
                }
                // If no events are left for this page, then remove it from the pageWithEventsMap
                if ( pg.evtCount < 1 ) {
                    delete BrowserAgent.globals.pageWithEventsMap[pgId];
                }
                // Capture cookies and send out in the first EUM on the page
                if ( pg.newPage === true && BrowserAgent.globals.configs.COOKIECAPTUREENABLED === true ) {
                    var cookies = BrowserAgent.jsonUtils.createCookies(BrowserAgent.cookieUtils.getAppCookies());
                    if ( cookies ) {
                        pgJSON.cookies = cookies;
                    }
                    pg.newPage = false;
                    isPgReady = true;
                }
                if ( isPgReady ) {
                    pgList.push(pgJSON);
                    // Toggle the page load flag
                    if ( pg.json.pageLoadFlag ) {
                        pg.json.pageLoadFlag = false;
                    }
                    // Toggle the new session flag
                    if ( pg.json.sessions.sessionList[0].newSessionFlag ) {
                        pg.json.sessions.sessionList[0].newSessionFlag = false;
                    }
                } else if ( pgJSON.pageLoadFlag === true ) {
                    // If pgJSON is going to be discarded, save its pageLoadFlag to the json shell so it can be sent
                    // out in the next harvest cycle.
                    pg.json.pageLoadFlag = true;
                }
            }
            if ( pgList.length > 0 ) {
                BrowserAgent.jsonUtils.updateEUMWithGeo(BrowserAgent.globals.eumJSONShell);
                eum = JSON.parse(JSON.stringify(BrowserAgent.globals.eumJSONShell));
                eum.app.ba.pages.pageList = pgList;
                BrowserAgent.evtUtils.sendEvts(BrowserAgent.globals.configs.COLLECTORURL, eum, true);
            }
        },
        /**
         * Dispatches the given event data to the given URL
         * @param URL
         * @param data
         * @param isAsync
         */
        sendEvts : function ( URL, data, isAsync ) {
            if ( !data || typeof URL !== 'string' ) {
                BrowserAgent.logger.error("sendMetrics: Cannot send Browser Agent Metrics to URL: " + URL +
                                          " with data as " + JSON.stringify(data));
                return;
            }
            // Default to Async
            if ( typeof isAsync !== 'boolean' ) {
                isAsync = true;
            }
            // Metrics will be sent via XHR Send. However, we do not want to
            // collect metrics for such an invocation of XHR Send. Redefine them to original.
            //TODO: Why do this? Can't we just instantiate this variable in browserUtils init and just use it?
            // Removed the if condition check, currently we need a new object every time
            // as the previous one may still be in use
            BrowserAgent.browserUtils.getXHRforBAMetrics();
            var xhr = BrowserAgent.browserUtils.XHRToSendMetrics;
            if ( !xhr ) {
                BrowserAgent.logger.error("sendMetrics: XHR could not be instantiated. Cannot send Browser Agent Metrics to URL: " +
                                          URL + " with data as " + JSON.stringify(data));
                return;
            }
            xhr.open("POST", URL, isAsync);
            if ( isAsync ) {
                xhr.onreadystatechange = function () {
                    if ( this.readyState === this.DONE ) {
                        if ( this.status === 204 ) {
                            BrowserAgent.logger.info("sendMetrics: Browser Agent app profile updated. Getting new app profile...");
                            BrowserAgent.configUtils.getAppProfile(BrowserAgent.globals.profileURL);
                        } else if ( this.status === 0 ) {
                            BrowserAgent.logger.error("sendMetrics : Browser Agent Metrics Send Error. Browser is most likely discarding them.");
                        }
                    }
                };
            }
            xhr.setRequestHeader("Content-type", "application/json; charset=utf-8");
            data = JSON.stringify(data);
            // For synchronous calls, if the browser supports sendBeacon API use it, otherwise make a
            // synchronous call
            if ( isAsync === false && navigator && navigator.sendBeacon ) {
                navigator.sendBeacon(URL, data);
            } else {
                xhr.send(data);
            }
            BrowserAgent.logger.debug("sendMetrics: Sending POST with " + data);
        }
    };
    /**
     * Page Utility
     * Responsible for Browser Agent HP and SP related tasks
     */
    BrowserAgent.pageUtils = {
        performance : null,
        /**
         * Page Utils intitialization
         */
        init : function () {
            BrowserAgent.globals.initPageInfo = {};
            BrowserAgent.globals.initPageInfo.url = window.location.href;
            BrowserAgent.globals.initPageInfo.timeStamp = BrowserAgent.globals.baStartTime;

            // Set page referrer. Clip at ? and ; so that only URI is passed.
            if ( document.referrer && document.referrer !== "" ) {
                BrowserAgent.globals.initPageInfo.referrer = BrowserAgent.browserUtils.trimURL(document.referrer);
                BrowserAgent.globals.initPageInfo.prevPage = BrowserAgent.globals.initPageInfo.referrer;
            }
            // Set page BS
            var businessService = BrowserAgent.jsonUtils.createBS(BrowserAgent.globals.bs,
                                                                  BrowserAgent.globals.bt,
                                                                  BrowserAgent.globals.btc);
            if ( businessService ) {
                BrowserAgent.globals.initPageInfo.businessService = businessService;
            }
            // Set page metric path
            BrowserAgent.globals.initPageInfo.pageMetricPath =
                BrowserAgent.globals.metricPathConsts.PREFIX + BrowserAgent.globals.pipeChar;
            var parser = BrowserAgent.browserUtils.parseURL(BrowserAgent.globals.initPageInfo.url);
            if ( BrowserAgent.globals.bs === BrowserAgent.globals.UNDEFINED ) {
                BrowserAgent.globals.initPageInfo.pageMetricPath +=
                    parser.hostname + BrowserAgent.globals.forwardSlashChar + parser.port +
                    BrowserAgent.globals.pipeChar + parser.pathname;
            } else {
                BrowserAgent.globals.initPageInfo.pageMetricPath +=
                    BrowserAgent.globals.bs + BrowserAgent.globals.pipeChar + BrowserAgent.globals.bt +
                    BrowserAgent.globals.pipeChar + BrowserAgent.globals.btc + BrowserAgent.globals.pipeChar +
                    BrowserAgent.globals.metricPathConsts.BROWSER;
            }
            // If initial url has hash, append it to pageMetricPath because all other events will use this metric path.
            // Create pageMetricPathNoHash for just the hard page load metrics.
            if ( parser.hash !== "" ) {
                BrowserAgent.globals.initPageInfo.pageMetricPathNoHash =
                    BrowserAgent.globals.initPageInfo.pageMetricPath;
                BrowserAgent.globals.initPageInfo.pageMetricPath += BrowserAgent.globals.pipeChar + parser.hash;
            }
            // Add the current hard page to the page buckets
            BrowserAgent.pageUtils.addNewPageBucket(BrowserAgent.globals.pageBucketTypes.HP,
                                                    BrowserAgent.globals.initPageInfo.url,
                                                    BrowserAgent.globals.initPageInfo.timeStamp, true,
                                                    BrowserAgent.browserUtils.cloneTrackerData());
            // If page load metrics are disabled, no need to instrument pages
            if ( !BrowserAgent.globals.configs.PAGELOADMETRICSENABLED ) {
                BrowserAgent.logger.info("pageUtils.init: Skipping page and soft page instrumentation because Page load metrics are DISABLED");
                BrowserAgent.globals.isSoftPageLoad = false;
            } else {
                // Check for Navigation Timing API
                if ( !this.performance || !this.performance.timing ) {
                    BrowserAgent.logger.warn("pageUtils.init: Navigation Timing API is not present. Page load metrics will not be reported...");
                } else {
                    BrowserAgent.logger.info("pageUtils.init: Navigation Timing API is present.");
                    // Attach to onload event on the bubbling phase
                    window.addEventListener("load", BrowserAgent.pageUtils.onload, false);
                }
            }
            // Check soft page instrumentation required browser APIs
            if ( !window.MutationObserver || !window.history ) {
                BrowserAgent.logger.warn("pageUtils.init: HTML5 history API is not present. Soft Page load metrics will not be reported...");
                BrowserAgent.globals.isSoftPageLoad = false;
            } else {
                // Edge and IE 11 has issues with popstate (not called in 99% of the use cases).
                // If this is an Edge or IE browser register for hashchange, still register with
                // the onpopstate function.
                if ( BrowserAgent.globals.userAgents.EDGE.name === BrowserAgent.globals.platform ||
                     BrowserAgent.globals.userAgents.IE.name === BrowserAgent.globals.platform ) {
                    window.addEventListener("hashchange", BrowserAgent.pageUtils.onpopstate, true);
                } else {
                    window.addEventListener("popstate", BrowserAgent.pageUtils.onpopstate, true);
                }

                // Create MutationObserver to watch DOM changes later
                BrowserAgent.globals.domChangeObserver = new MutationObserver(function ( mutations ) {
                    BrowserAgent.globals.domLastUpdated = Date.now();
                    if ( !BrowserAgent.globals.domChangeTimerId ) {
                        // First DOM change
                        // Add mouse interaction listener
                        document.addEventListener('mousedown', BrowserAgent.pageUtils.mouseEventHandler, true);
                        document.addEventListener('scroll', BrowserAgent.pageUtils.mouseEventHandler, true);
                        // Set interval to check DOM change
                        BrowserAgent.globals.domChangeTimerId = setInterval(BrowserAgent.pageUtils.checkLastDOMChange,
                                                                            BrowserAgent.globals.configs.DOMCHANGEINTERVAL);
                    }
                });
            }
        },
        /**
         * Adds a new page bucket of type HP or SP to the pageBucketsMap
         * @param type
         * @param url
         * @param ts
         * @param loadFlag
         * @param axaData
         */
        addNewPageBucket : function ( type, url, ts, loadFlag, axaData ) {
            if ( !BrowserAgent.globals.configs.BROWSERAGENTENABLED ) {
                return;
            }
            var id = BrowserAgent.globals.getSequenceNum();
            var data = {
                json : {
                    url : url,
                    pageLoadFlag : !BrowserAgent.globals.configs.PAGELOADMETRICSENABLED,
                    pageType : type,
                    sessions : { sessionList : [] }
                },
                evtMap : {},
                evtCount : 0,
                isExcluded : BrowserAgent.configUtils.isUrlExcluded(url)
            };
            if ( data.isExcluded ) {
                BrowserAgent.logger.info("addNewPageBucket: Page [" + url +
                                         "] is configured to be EXCLUDED. Skipping all instrumentation on this page...");
            }
            var isRefreshSession = false;
            if ( loadFlag === false ) {
                data.json.timeStamp = BrowserAgent.globals.currPagePtr.json.timeStamp;
                isRefreshSession = true;
            } else {
                if ( !BrowserAgent.browserUtils.isSameSession(ts) ) {
                    isRefreshSession = true;
                }
                data.json.timeStamp = ts;
            }
            if ( isRefreshSession ) {
                BrowserAgent.globals.currSession = BrowserAgent.browserUtils.getNewSession(ts);
            }
            // Update last event timeStamp
            BrowserAgent.storageUtils.putInStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                   BrowserAgent.storageUtils.storageKeys.BALASTEVENT_TIME,
                                                   ts, true);
            // Clone current session info
            if ( BrowserAgent.globals.currSession.id ) {
                var sessionInfo = { id : BrowserAgent.globals.currSession.id };
                if ( typeof BrowserAgent.globals.currSession.startTime === 'number' ) {
                    sessionInfo.startTime = BrowserAgent.globals.currSession.startTime;
                }
                if ( typeof BrowserAgent.globals.currSession.isNewSession === 'boolean' ) {
                    sessionInfo.newSessionFlag = BrowserAgent.globals.currSession.isNewSession;
                }
                data.json.sessions.sessionList.push(sessionInfo);
                if ( BrowserAgent.globals.currSession.isNewSession ) {
                    BrowserAgent.globals.currSession.isNewSession = false;
                }
            }
            BrowserAgent.globals.pageBucketsMap[id] = data;
            // Set current page and prev page
            BrowserAgent.globals.prevPagePtr = BrowserAgent.globals.currPagePtr;
            BrowserAgent.globals.currPagePtr = BrowserAgent.globals.pageBucketsMap[id];
            BrowserAgent.globals.currPagePtr.id = id;
            if ( type === BrowserAgent.globals.pageBucketTypes.HP ) {
                BrowserAgent.globals.initPageInfo.id = id;
                if ( BrowserAgent.globals.initPageInfo.referrer ) {
                    data.json.referrer = { url : BrowserAgent.globals.initPageInfo.referrer };
                    data.json.prevPage = {
                        url : BrowserAgent.globals.initPageInfo.prevPage,
                        timeStamp : BrowserAgent.globals.initPageInfo.timeStamp
                    };
                }
                if ( BrowserAgent.globals.initPageInfo.businessService ) {
                    data.json.businessService = BrowserAgent.globals.initPageInfo.businessService;
                }
                data.pageMetricPath = BrowserAgent.globals.initPageInfo.pageMetricPath;
                if ( loadFlag === true ) { // hard page load
                    data.newPage = true;
                }
            } else {
                data.json.referrer = {
                    url : BrowserAgent.globals.initPageInfo.url, timeStamp : BrowserAgent.globals.initPageInfo.timeStamp
                };
                data.json.prevPage = {
                    url : BrowserAgent.globals.prevPagePtr.json.url,
                    timeStamp : BrowserAgent.globals.prevPagePtr.json.timeStamp
                };
                var parser = BrowserAgent.browserUtils.parseURL(url);
                if ( BrowserAgent.globals.initPageInfo.businessService ) {
                    data.json.businessService = BrowserAgent.jsonUtils.createBS(BrowserAgent.globals.bs,
                                                                                BrowserAgent.globals.bt,
                                                                                BrowserAgent.globals.btc);
                    data.pageMetricPath =
                        BrowserAgent.globals.metricPathConsts.PREFIX + BrowserAgent.globals.pipeChar +
                        BrowserAgent.globals.bs + BrowserAgent.globals.pipeChar + BrowserAgent.globals.bt +
                        BrowserAgent.globals.pipeChar +
                        BrowserAgent.globals.btc + BrowserAgent.globals.pipeChar +
                        BrowserAgent.globals.metricPathConsts.BROWSER +
                        (parser.hash === "" ? "" : BrowserAgent.globals.pipeChar + parser.hash);
                } else {
                    data.pageMetricPath =
                        BrowserAgent.globals.metricPathConsts.PREFIX + BrowserAgent.globals.pipeChar + parser.hostname +
                        BrowserAgent.globals.forwardSlashChar + parser.port + BrowserAgent.globals.pipeChar +
                        parser.pathname + (parser.hash === "" ? "" : BrowserAgent.globals.pipeChar + parser.hash);
                }
            }
            BrowserAgent.globals.pageBucketsIdList.push(id);
            // Calculate think time
            if ( BrowserAgent.globals.currTTimeEvtPtr ) {
                BrowserAgent.globals.currTTimeEvtPtr.e = ts;
                BrowserAgent.globals.currTTimeEvtPtr.isDone = true;
            }
            var evtObj = BrowserAgent.evtUtils.getEvtObject(BrowserAgent.globals.evtTypes.TTIME, false, null);
            if ( evtObj ) {
                evtObj.s = ts;
                evtObj[BrowserAgent.globals.trackerDataKey] = axaData;
            }
            BrowserAgent.globals.currTTimeEvtPtr = evtObj;
            // Age out the oldest page, if # of page buckets > pageBucketsMaxLen
            if ( BrowserAgent.globals.pageBucketsIdList.length > BrowserAgent.globals.pageBucketsMaxLen ) {
                //TODO: Enhancement, if there are events done on this page, then mark it for deletion and
                // delete it once the harvest cycle is complete
                var oldest = BrowserAgent.globals.pageBucketsIdList[0];
                delete BrowserAgent.globals.pageBucketsMap[oldest];
                delete BrowserAgent.globals.pageWithEventsMap[oldest];
                BrowserAgent.globals.pageBucketsIdList.shift();
            }
        },
        /**
         * onpopstate event handler.
         * @param event
         */
        onpopstate : function ( event ) {
            // Set soft navigation start
            var now = Date.now();
            var td = BrowserAgent.browserUtils.cloneTrackerData();
            // Create a new SP Bucket
            BrowserAgent.pageUtils.addNewPageBucket(BrowserAgent.globals.pageBucketTypes.SP, window.location.href, now,
                                                    true, td);
            if ( BrowserAgent.globals.domChangeTimeoutId || BrowserAgent.globals.domChangeTimerId ) {
                // Still tracking DOM changes from last route change. End it.
                BrowserAgent.logger.debug("onpopstate: DOM change tracking terminated by new route change.");
                BrowserAgent.pageUtils.endDomTracking(now);
            }
            if ( BrowserAgent.globals.isSoftPageLoad ) {
                BrowserAgent.pageUtils.startDomTracking(now, td);
            }
        },
        /**
         * Disable Soft Page instrumentation.
         */
        disableSoftPages : function () {
            if ( BrowserAgent.globals.domChangeTimeoutId || BrowserAgent.globals.domChangeTimerId ) {
                // Still tracking DOM changes from last route change. Clear them.
                BrowserAgent.pageUtils.clearDomChangeTrackers();
            }
            BrowserAgent.globals.isSoftPageLoad = false;
        },
        /**
         * Mouse event handler for click and scroll.
         */
        mouseEventHandler : function () {
            var now = Date.now();
            if ( BrowserAgent.globals.domChangeTimeoutId || BrowserAgent.globals.domChangeTimerId ) {
                // DOM change tracking terminated by user interaction
                BrowserAgent.logger.debug("mouseEventHandler: DOM change tracking terminated by user interaction.");
                BrowserAgent.pageUtils.endDomTracking(now);
            }
        },
        /**
         * Checks if there is DOM change in the past interval.
         */
        checkLastDOMChange : function () {
            var now = Date.now();
            if ( now > (BrowserAgent.globals.domLastUpdated + BrowserAgent.globals.configs.DOMCHANGEINTERVAL) ) {
                // DOM change hasn't happen in time set in domChangeInterval so we assume DOM change has ended.
                BrowserAgent.logger.debug("checkLastDOMChange: DOM has finished loading.");
                BrowserAgent.pageUtils.endDomTracking(BrowserAgent.globals.domLastUpdated);
            }
        },
        /**
         * Starts DOM tracking.
         * @param startTime
         * @param trackerData - Snapshot of tracker data list at the start of a route change
         */
        startDomTracking : function ( startTime, trackerData ) {
            if ( startTime > 0 ) {
                var evtObj = BrowserAgent.evtUtils.getEvtObject(BrowserAgent.globals.evtTypes.SPLOAD, false, null);
                if ( evtObj ) {
                    BrowserAgent.globals.domChangeTimeoutId = setTimeout(function () {
                        BrowserAgent.logger.debug("endDomTracking: DOM change tracking timed out.");
                        BrowserAgent.pageUtils.endDomTracking(Date.now());
                    }, BrowserAgent.globals.configs.DOMCHANGETIMEOUT);

                    BrowserAgent.globals.softPageLoadEvtObj = evtObj;
                    evtObj[BrowserAgent.globals.softPageDataKeys.START] = startTime;
                    evtObj[BrowserAgent.globals.trackerDataKey] = trackerData;
                    // Watch DOM change for soft navigation end
                    BrowserAgent.globals.domChangeObserver.observe(document,
                                                                   BrowserAgent.globals.domChangeObserverConfig);
                }
            } else {
                BrowserAgent.logger.error("startDomTracking: startTime is invalid.");
            }
        },
        /**
         * Ends DOM tracking.
         * @param endTime
         */
        endDomTracking : function ( endTime ) {
            if ( endTime > 0 ) {
                var domLastUpdated = BrowserAgent.globals.domLastUpdated;
                BrowserAgent.pageUtils.clearDomChangeTrackers();
                if ( !domLastUpdated ) {
                    // If DOM has changed before timeout, keep the data point
                    endTime = BrowserAgent.globals.softPageLoadEvtObj[BrowserAgent.globals.softPageDataKeys.START];
                }
                BrowserAgent.globals.softPageLoadEvtObj[BrowserAgent.globals.softPageDataKeys.END] = endTime;
                BrowserAgent.globals.softPageLoadEvtObj.isDone = true;
            } else {
                BrowserAgent.logger.error("endDomTracking: Input is invalid.");
            }
        },
        /**
         * Clears all DOM change listeners and timers.
         */
        clearDomChangeTrackers : function () {
            BrowserAgent.globals.domChangeObserver.disconnect();
            BrowserAgent.globals.domLastUpdated = null;
            clearInterval(BrowserAgent.globals.domChangeTimerId);
            BrowserAgent.globals.domChangeTimerId = null;
            clearTimeout(BrowserAgent.globals.domChangeTimeoutId);
            BrowserAgent.globals.domChangeTimeoutId = null;
            document.removeEventListener('mousedown', BrowserAgent.pageUtils.mouseEventHandler, true);
            document.removeEventListener('scroll', BrowserAgent.pageUtils.mouseEventHandler, true);
        },
        /**
         *  Callback Function for the window.onload event
         */
        onload : function () {
            BrowserAgent.logger.info("onload: Detected 'onload' event...");
            // Some of the page load metrics such as loadEventEnd isn't set until all onload call backs have
            // completed. What this timeout is doing is allows onload function to complete thus the timing API
            // can set loadEventEnd time value.  Then immediately following that chain of calls, onloadHelper
            // will be triggered next in the queue sending the metrics where loadEventEnd is now set.
            setTimeout(function () {
                BrowserAgent.pageUtils.onloadHelper();
            }, 0);
        },
        /**
         * Don't call directly, helper function for onload function.
         */
        onloadHelper : function () {
            // Moved from BrowserAgent.pageUtils.init where onload function was attached.  The following only
            // runs for browsers supporting the navigation timing API.
            BrowserAgent.logger.info("onloadHelper: OnloadHelper has started");
            // Check if page is excluded
            var pageBucket = BrowserAgent.globals.pageBucketsMap[BrowserAgent.globals.initPageInfo.id];
            if ( pageBucket.isExcluded ) {
                return;
            }
            // Add the page load event
            // Note: Here, don't use the getEvtObject as PLOAD evt should always point to the initial page object
            var id = BrowserAgent.globals.getSequenceNum();
            pageBucket.evtMap[id] = {
                id : id,
                type : BrowserAgent.globals.evtTypes.HPLOAD,
                raw : BrowserAgent.pageUtils.performance.timing,
                isDone : true
            };
            pageBucket.evtMap[id][BrowserAgent.globals.trackerDataKey] = BrowserAgent.browserUtils.cloneTrackerData();
            pageBucket.evtCount += 1;
            BrowserAgent.globals.pageWithEventsMap[BrowserAgent.globals.initPageInfo.id] = 1;
        },
        /**
         * Calculates the current page's think time upon unload event
         */
        tTimeHandler : function () {
            if ( BrowserAgent.globals.tTimeHandlerFlag ) {
                return;
            }
            if ( !BrowserAgent.globals.currTTimeEvtPtr ) {
                return;
            }
            BrowserAgent.globals.currTTimeEvtPtr.e = Date.now();
            BrowserAgent.globals.currTTimeEvtPtr.isDone = true;
            // Clear the harvest interval
            if ( BrowserAgent.globals.harvestIntervalId ) {
                clearInterval(BrowserAgent.globals.harvestIntervalId);
                BrowserAgent.globals.harvestIntervalId = null;
            }
            var pgJSON = JSON.parse(JSON.stringify(BrowserAgent.globals.currPagePtr.json));
            var result = BrowserAgent.evtUtils.handleTTimeEvt(BrowserAgent.globals.currPagePtr.pageMetricPath,
                                                              pgJSON, BrowserAgent.globals.currTTimeEvtPtr);
            BrowserAgent.globals.tTimeHandlerFlag = true;
            if ( !result ) {
                return;
            }
            BrowserAgent.jsonUtils.updateEUMWithGeo(BrowserAgent.globals.eumJSONShell);
            var eum = JSON.parse(JSON.stringify(BrowserAgent.globals.eumJSONShell));
            eum.app.ba.pages.pageList = [pgJSON];
            BrowserAgent.evtUtils.sendEvts(BrowserAgent.globals.configs.COLLECTORURL, eum, false);
        }
    };

    if ( typeof BrowserAgentExtension !== 'undefined' ) {
        /**
         * An array that holds custom page metrics and is reset every metric harvest cycle.
         */
        BrowserAgentExtension.extCustomPageMetricList = [];
        /**
         * An array that holds custom JS function metrics and is reset every metric harvest cycle.
         */
        BrowserAgentExtension.extCustomJSFuncMetricList = [];
        /**
         * An array that holds custom Ajax metrics and is reset every metric harvest cycle.
         */
        BrowserAgentExtension.extCustomAjaxMetricList = [];
        /**
         * An array that holds custom transaction trace optional properties and is reset every metric harvest
         * cycle.
         */
        BrowserAgentExtension.extCustomOptionalPropertyList = [];
        /**
         * BrowserAgent JS Extension Utilities
         */
        BrowserAgentExtension.internal = {
            createAXAEvent : function ( eventId, eventName, eventType, eventValue, timeStamp, url, responseTime,
                                        statusCode, dataIn, dataOut, countryCode, zipCode, latitude, longitude,
                                        x_AttrList ) {
                var axaEvent = {};
                if ( typeof eventId === 'number' && !isNaN(eventId) ) {
                    axaEvent.eventId = eventId;
                }
                if ( typeof eventName === 'string' ) {
                    axaEvent.eventName = eventName;
                }
                if ( typeof eventType === 'string' ) {
                    axaEvent.eventType = eventType;
                }
                if ( typeof eventValue === 'string' || typeof eventValue === 'number' ) {
                    axaEvent.eventValue = eventValue.toString();
                }
                if ( typeof timeStamp === 'number' && !isNaN(timeStamp) ) {
                    axaEvent.timeStamp = timeStamp;
                }
                if ( typeof url === 'string' ) {
                    axaEvent.url = url;
                }
                if ( typeof responseTime === 'number' && !isNaN(responseTime) ) {
                    axaEvent.responseTime = responseTime;
                }
                if ( typeof statusCode === 'number' && !isNaN(statusCode) ) {
                    axaEvent.statusCode = statusCode;
                }
                if ( typeof dataIn === 'number' && !isNaN(dataIn) ) {
                    axaEvent.dataIn = dataIn;
                }
                if ( typeof dataOut === 'number' && !isNaN(dataOut) ) {
                    axaEvent.dataOut = dataOut;
                }
                if ( typeof countryCode === 'string' ) {
                    axaEvent.countryCode = countryCode;
                }
                if ( typeof zipCode === 'string' ) {
                    axaEvent.zipCode = zipCode;
                }
                if ( typeof latitude === 'string' ) {
                    axaEvent.latitude = latitude;
                }
                if ( typeof longitude === 'string' ) {
                    axaEvent.longitude = longitude;
                }
                if ( x_AttrList && x_AttrList.length > 0 ) {
                    axaEvent.x_attributes = { x_attributeList : x_AttrList };
                }
                return axaEvent;
            },
            /**
             * Adds AXA Data to a global tracker data map as well as into the AXA events
             * @param data - AXA data object. If the data object contains trackerData sub object, then store
             *     trackerData in the global tracker data map
             */
            addAXAData : function ( data ) {
                try {
                    if ( BrowserAgent.globals.configs.BROWSERAGENTENABLED === false ) {
                        return;
                    }
                    if ( data === null || typeof data !== 'object' ) {
                        BrowserAgent.logger.warn("BrowserAgentExtension.internal.addAXAData: Cannot add data due to invalid input");
                        return;
                    }
                    var evtObj = BrowserAgent.evtUtils.getEvtObject(BrowserAgent.globals.evtTypes.AXAEXT, false, null);
                    if ( !evtObj ) {
                        return;
                    }
                    var tkrAttrList = [], x_AttrList = [], item;
                    var result, trkrData = JSON.parse(BrowserAgent.storageUtils.getFromStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                                                               BrowserAgent.storageUtils.storageKeys.BATRKR));
                    // Store the tracker data in the global tracker data map
                    if ( typeof data.trackerId === 'string' && data.trackerData !== null &&
                         typeof data.trackerData === 'object' ) {
                        // Prevent trackerData overwrite
                        if ( trkrData && trkrData.trackerId ) {
                            return;
                        }
                        // Create an X_Attr of the tracker data attributes
                        for ( item in data.trackerData ) {
                            result = BrowserAgent.jsonUtils.createXAttribute(item, data.trackerData[item]);
                            if ( result ) {
                                tkrAttrList.push(result);
                            }
                        }
                        trkrData = {};
                        trkrData[data.trackerId] = { x_attributes : { x_attributeList : tkrAttrList } };
                        BrowserAgent.storageUtils.putInStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                               BrowserAgent.storageUtils.storageKeys.BATRKR,
                                                               JSON.stringify(trkrData),
                                                               true);
                    } else {
                        // No trackerID or trackerData or both
                        // Just clone current trackerData and append it to the attr list
                        for ( var td in trkrData ) {
                            x_AttrList = x_AttrList.concat(trkrData[td].x_attributes.x_attributeList);
                        }
                    }
                    // If there are { key, value } pairs, then append it to the attr list
                    if ( data.attr ) {
                        for ( item in data.attr ) {
                            result = BrowserAgent.jsonUtils.createXAttribute(item, data.attr[item]);
                            if ( result ) {
                                x_AttrList.push(result);
                            }
                        }
                    }
                    // Create an AXA event object out of the given data
                    result =
                        BrowserAgentExtension.internal.createAXAEvent(data.eid, data.n, data.ty, data.v, data.t, data.u,
                                                                      data.r, data.s, data.i, data.o, data.cc, data.zp,
                                                                      data.la, data.lo, x_AttrList);
                    if ( !result ) {
                        evtObj.isDelete = true;
                        return;
                    }
                    // Add an AXA EXT event to the event map of the current page
                    evtObj.d = result;
                    evtObj.isDone = true;
                } catch ( e ) {
                    if ( evtObj ) {
                        evtObj.isDelete = true;
                    }
                }
            },
            /**
             * Erases the data (marked with the given tracker ID) from the global tracker data map
             * @param trackerId - must be the same tracker ID with which the tracker data was stored
             */
            clearTracker : function ( trackerId ) {
                var td;
                try {
                    if ( typeof trackerId !== 'string' || trackerId.length < 1 ) {
                        BrowserAgent.logger.warn("BrowserAgentExtension.internal.clearTracker: Cannot clear data for tracker ID [" +
                                                 trackerId + "]");
                    }
                    td =
                        JSON.parse(BrowserAgent.storageUtils.getFromStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                                            BrowserAgent.storageUtils.storageKeys.BATRKR));
                    if ( td && td[trackerId] ) {
                        delete td[trackerId];
                        // No need to verify corner cases here as getFromStorage already does
                        BrowserAgent.storageUtils.putInStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                               BrowserAgent.storageUtils.storageKeys.BATRKR,
                                                               JSON.stringify(td), true);
                    }
                } catch ( e ) {
                    BrowserAgent.logger.error("BrowserAgentExtension.internal.clearTracker: Cannot clear data for tracker ID [" +
                                              trackerId + "] - " + e.message);
                }
            },
            clearAllTrackers : function () {
                try {
                    if ( !BrowserAgent.globals.isStoragePresent ) {
                        return;
                    }
                    sessionStorage.removeItem(BrowserAgent.storageUtils.storageKeys.BATRKR);
                } catch ( e ) {
                    BrowserAgent.logger.error("BrowserAgentExtension.internal.clearAllTrackers: Cannot clear tracker data - " +
                                              e.message);
                }
            },
            /**
             * Obtains the tracker data given an id
             * @param trackerId
             * @returns {*}
             */
            getTrackerDataById : function ( trackerId ) {
                try {
                    var td = JSON.parse(BrowserAgent.storageUtils.getFromStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                                                 BrowserAgent.storageUtils.storageKeys.BATRKR));
                    if ( !td || !td[trackerId] ) {
                        return null;
                    }
                    return td[trackerId];
                } catch ( e ) {
                    BrowserAgent.logger.error("BrowserAgentExtension.internal.getTrackerDataById: Cannot obtain data for tracker ID [" +
                                              trackerId + "] - " + e.message);
                    return null;
                }
            }
        };
        /**
         * BrowserAgent JS Extension API implementations
         */
            // APM
        BrowserAgentExtension.createCustomMetric = function ( name, unit, type, value, path ) {
            return {
                name : name,
                unit : unit,
                accumulatorType : type,
                value : value,
                path : path
            };
        };
        BrowserAgentExtension.addExtensionJSONObject = function ( metricList ) {
            try {
                if ( BrowserAgent.globals.configs.BROWSERAGENTENABLED === false ) {
                    return;
                }
                if ( !metricList || metricList.length === 0 ) {
                    BrowserAgent.logger.warn("addExtensionJSONObject: Invalid metric list. Discard extension JSON object...");
                    return;
                }
                var evtObj = BrowserAgent.evtUtils.getEvtObject(BrowserAgent.globals.evtTypes.APMEXT, false, null);
                if ( !evtObj ) {
                    return;
                }
                for ( var i in metricList ) {
                    var metric = metricList[i];
                    if ( !metric || !BrowserAgent.jsonUtils.validateMetric(metric.path, metric.name, metric.unit,
                                                                           metric.accumulatorType,
                                                                           metric.value) ) {
                        BrowserAgent.logger.warn("addExtensionJSONObject: Invalid metric list. Discard extension JSON object...");
                        evtObj.isDelete = true;
                        return;
                    }
                }
                evtObj.lst = metricList;
                evtObj.isDone = true;
            } catch ( e ) {
                if ( evtObj ) {
                    evtObj.isDelete = true;
                }
            }
        };
        BrowserAgentExtension.addCustomOptionalProperty = function ( name, value, description ) {
            BrowserAgentExtension.extCustomOptionalPropertyList.push({
                name : name,
                value : value,
                description : description
            });
        };
        BrowserAgentExtension.addCustomAjaxMetric = function ( name, unit, type, value ) {
            BrowserAgentExtension.extCustomAjaxMetricList.push(BrowserAgentExtension.createCustomMetric(name, unit,
                                                                                                        type,
                                                                                                        value));
        };
        BrowserAgentExtension.addCustomJSFuncMetric = function ( name, unit, type, value ) {
            BrowserAgentExtension.extCustomJSFuncMetricList.push(BrowserAgentExtension.createCustomMetric(name, unit,
                                                                                                          type,
                                                                                                          value));
        };
        BrowserAgentExtension.addCustomPageMetric = function ( name, unit, type, value ) {
            BrowserAgentExtension.extCustomPageMetricList.push(BrowserAgentExtension.createCustomMetric(name, unit,
                                                                                                        type,
                                                                                                        value));
        };
        BrowserAgentExtension.addJSFuncToInstrument = function ( functionName, preTracerList, postTracerList ) {
            BrowserAgent.funcUtils.addFuncToCollection(BrowserAgent.globals.extFuncMap, functionName, preTracerList,
                                                       postTracerList);
        };
        // AXA
        BrowserAgentExtension.logTextMetric = function ( evt ) {
            if ( !evt ) {
                BrowserAgent.logger.warn("Event " + evt + " is not valid. Please pass a valid logTextMetric event");
                return;
            }
            var ba = new Object();
            var key = evt.key;
            var val = evt.value;
            var attributes = evt.attributes;
            if ( !attributes ) {
                attributes = new Object();
            }
            attributes.dty = "string";
            if ( key && val ) {
                ba.ty = "custom";
                ba.n = key;
                ba.v = val;
                ba.attr = attributes;
                ba.t = (new Date).getTime();
                BrowserAgentExtension.internal.addAXAData(ba);
            } else {
                BrowserAgent.logger.warn("Event " + evt + " is not valid. Please pass a valid logTextMetric event");
            }
        };
        BrowserAgentExtension.logNumericMetric = function ( evt ) {
            if ( !evt ) {
                BrowserAgent.logger.warn("Event " + evt + " is not valid. Please pass a valid logNumericMetric event");
                return;
            }
            var ba = new Object();
            var key = evt.key;
            var val = evt.value;
            var attributes = evt.attributes;
            if ( !attributes ) {
                attributes = new Object();
            }
            attributes.dty = "double";
            if ( key && val ) {
                ba.ty = "custom";
                ba.n = key;
                ba.v = val;
                ba.attr = attributes;
                ba.t = (new Date).getTime();
                BrowserAgentExtension.internal.addAXAData(ba);
            } else {
                BrowserAgent.logger.warn("Event " + evt + " is not valid. Please pass a valid logNumericMetric event");
            }
        };
        BrowserAgentExtension.setCustomerLocation = function ( location ) {
            if ( !location ) {
                BrowserAgent.logger.warn("setCustomerLocation " + location +
                                         " is not valid. Please pass a valid setCustomerLocation event");
                return;
            }

            var ba = {};
            var zipCode = location.zipCode;
            var countryCode = location.countryCode;
            var attributes = location.attributes;
            var latitude = location.latitude;
            var longitude = location.longitude;
            if ( !attributes ) {
                attributes = {};
            }
            ba.ty = "sessionEvent";
            ba.n = "customerLocation";
            var eventSet = false;
            if ( zipCode && countryCode ) {
                ba.zp = zipCode;
                ba.cc = countryCode;
                eventSet = true;
            }
            if ( latitude && longitude ) {
                ba.la = latitude;
                ba.lo = longitude;

                // Adds custom location to session storage. To be used as apm location
                // across pages even if application geolocation is disabled.
                var customLocation = { lat : Number(latitude), lon : Number(longitude) };
                var customLocationStr = JSON.stringify(customLocation);
                BrowserAgent.storageUtils.putInStorage(BrowserAgent.storageUtils.storageTypes.SESSION,
                                                       BrowserAgent.storageUtils.storageKeys.GEOCUSTOM,
                                                       customLocationStr, true);

                eventSet = true;
            }
            if ( eventSet ) {
                ba.attr = attributes;
                ba.t = (new Date()).getTime();
                BrowserAgentExtension.internal.addAXAData(ba);
            }
            else {
                BrowserAgent.logger.warn("setCustomerLocation " + location +
                                         " is not valid. Please pass a valid setCustomerLocation location");
            }
        };
        BrowserAgentExtension.setSessionAttribute = function ( evt ) {
            if ( !evt ) {
                BrowserAgent.logger.warn("Event " + evt + " is not valid. Please pass a valid setSessionAttribute event");
                return;
            }
            var ba = new Object();
            var key = evt.key;
            var value = evt.value;
            var batype = "string";
            if ( batype ) {
                batype = evt.type;
            }
            var attributes = evt.attributes;
            if ( !attributes ) {
                attributes = new Object();
            }
            ba.ty = "sessionEvent";
            if ( key && value ) {
                ba.n = key;
                ba.v = value;
                ba.attr = attributes;
                ba.attr.dty = batype;
                ba.t = (new Date).getTime();
                BrowserAgentExtension.internal.addAXAData(ba);
            } else {
                BrowserAgent.logger.warn("Event " + evt + " is not valid. Please pass a valid setSessionAttribute event");
            }
        };
        BrowserAgentExtension.startApplicationTransaction = function ( evt ) {
            if ( !evt ) {
                BrowserAgent.logger.warn("Event " + evt +
                                         " is not valid. Please pass a valid startApplicationTransaction  event");
                return;
            }
            var ba = new Object();
            var txnName = evt.transactionName;
            var txnService = evt.serviceName;
            var txnType = "txn_events";
            var txnEventName = "apptxn_start";
            var attributes = evt.attributes;

            if ( !attributes ) {
                attributes = new Object();
            }

            if ( txnName ) {
                var timeNow = (new Date).getTime();
                ba.ty = txnType;
                ba.n = txnEventName;
                ba.v = txnName;
                ba.attr = attributes;
                ba.attr.mode = "MANUAL";
                ba.attr.txn_s = timeNow;
                var trackerId = txnName;
                ba.trackerData = new Object();
                if ( txnService ) {
                    ba.attr.ca_as = txnService;
                    ba.trackerData.ca_as = txnService;
                    trackerId = txnName + "-" + txnService;
                }
                var existingTrackerId = BrowserAgentExtension.internal.getTrackerDataById(trackerId);
                if ( existingTrackerId ) {
                    BrowserAgent.logger.info("AXA Transaction with transaction tracker " + trackerId +
                                             " already started");
                    return;
                }
                // TODO : check if it exists and do not log a transaction Event.
                ba.trackerId = trackerId;
                ba.trackerData.ca_at = txnName;
                ba.trackerData.txn_s = timeNow;
                ba.t = timeNow;
                BrowserAgentExtension.internal.addAXAData(ba);
            } else {
                BrowserAgent.logger.warn("Event " + evt +
                                         " is not valid. Please pass a valid startApplicationTransaction  event");
            }
        };
        BrowserAgentExtension.stopApplicationTransaction = function ( evt ) {
            if ( !evt ) {
                BrowserAgent.logger.warn("Event " + evt +
                                         " is not valid. Please pass a valid stopApplicationTransaction event");
                return;
            }
            var ba = new Object();
            var txnName = evt.transactionName;
            var txnService = evt.serviceName;
            var txnType = "txn_events";
            var txnEventName = "apptxn_end";
            var failure = evt.failure;

            if ( failure ) {
                txnEventName = "apptxn_fail";
            }

            var attributes = evt.attributes;
            if ( !attributes ) {
                attributes = new Object();
            }
            if ( txnName ) {
                var timeNow = (new Date).getTime();
                ba.ty = txnType;
                ba.n = txnEventName;
                ba.v = txnName;
                ba.attr = attributes;
                ba.attr.mode = "MANUAL";
                // ba.attr.txn_s = timeNow;
                if ( failure ) {
                    ba.attr.fd = failure;
                }
                var trackerId = txnName;
                if ( txnService ) {
                    ba.attr.ca_as = txnService;
                    trackerId = txnName + "-" + txnService;
                }
                ba.t = timeNow;
                var existingTrackerId = trackerId;
                var existingTrackerId = BrowserAgentExtension.internal.getTrackerDataById(trackerId);
                if ( existingTrackerId ) {
                    BrowserAgentExtension.internal.addAXAData(ba);
                    BrowserAgentExtension.internal.clearTracker(trackerId);
                } else {
                    BrowserAgent.logger.info("Cannot stop AXA Transaction with transaction tracker " +
                                             existingTrackerId + ". Please check if transaction is started");
                }
                //TODO : check if it exists , if it does not - dont stop the transaction.
            }
        };
        BrowserAgentExtension.logNetworkEvent = function ( evt ) {
            if ( !evt ) {
                BrowserAgent.logger.warn("Event " + evt +
                                         " is not valid. Please pass a valid logNetworkEvent event");
                return;
            }
            var ba = new Object();
            ba.u = evt.url;
            ba.s = evt.status;
            ba.i = evt.inbytes;
            ba.o = evt.outbytes;
            ba.r = evt.time;
            var attributes = evt.attributes;
            if ( !attributes ) {
                attributes = new Object();
            }
            if ( ba.u && ba.s && ba.i && ba.o && ba.r ) {
                ba.ty = "network";
                ba.attr = attributes;
                ba.t = (new Date).getTime();
                BrowserAgentExtension.internal.addAXAData(ba);
            } else {
                BrowserAgent.logger.warn("Event " + evt +
                                         " is not valid. Please pass a valid network event with url,in bytes , out bytes , status and response time");
            }
        };
        BrowserAgentExtension.setCustomerId = function ( evt ) {
            if ( !evt ) {
                BrowserAgent.logger.warn("Event " + evt + " is not valid. Please pass a valid setCustomerId event");
                return;
            }
            var ba = new Object();
            var key = "customerId";
            if ( !evt.customerId ) {
                BrowserAgent.logger.warn("Event " + evt + " is not valid. Please pass a valid customerId in event");
                return;
            }
            var value = evt.customerId;

            var attributes = evt.attributes;
            if ( !attributes ) {
                attributes = new Object();
            }
            ba.ty = "sessionEvent";
            if ( key && value ) {
                ba.n = key;
                ba.v = value;
                ba.attr = attributes;
                ba.t = (new Date).getTime();
                BrowserAgentExtension.internal.addAXAData(ba);
            } else {
                BrowserAgent.logger.warn("Event " + evt + " is not valid. Please pass a valid setCustomerId event");
            }
        };
    }

    /**
     * This is the entry function into BA
     */
    BrowserAgent.main = function () {
        // Shim the 'now' method for browsers that do not support it
        if ( !Date.now ) {
            Date.now = function () {
                return new Date().getTime();
            };
        }
        // Polyfill String prototype's includes method
        if ( !String.prototype.includes ) {
            String.prototype.includes = BrowserAgent.browserUtils.includes;
        }
        // Set the configs to defaults
        BrowserAgent.globals.configs = JSON.parse(JSON.stringify(BrowserAgent.configUtils.defaults));
        BrowserAgent.globals.configs.BROWSERLOGGINGENABLED = true;

        BrowserAgent.pageUtils.performance = window.performance;
        BrowserAgent.globals.baStartTime =
            (BrowserAgent.pageUtils.performance && BrowserAgent.pageUtils.performance.timing &&
             BrowserAgent.pageUtils.performance.timing.navigationStart) ?
            BrowserAgent.pageUtils.performance.timing.navigationStart : Date.now();
        // Check if platform cookie is already set. If so, check is platform cookie is supported.
        // If not, parse user agent and set platform cookie.
        var platformCookie = BrowserAgent.cookieUtils.getRawCookie(BrowserAgent.cookieUtils.cookies.PLATFORM);
        if ( platformCookie ) {
            if ( platformCookie === BrowserAgent.globals.userAgents.UNSUPPORTED.name ) {
                BrowserAgent.logger.warn("BrowserAgent.main: Unsupported browser. Disabling Browser Agent ...");
                return;
            }
        } else {
            var browserInfo = BrowserAgent.browserUtils.getBrowserInfo(navigator.userAgent);
            // Set user agent cookies
            BrowserAgent.cookieUtils.setRawCookie(BrowserAgent.cookieUtils.cookies.PLATFORM,
                                                  browserInfo.name, null, "/", null);
            BrowserAgent.cookieUtils.setRawCookie(BrowserAgent.cookieUtils.cookies.PLATFORMVER,
                                                  browserInfo.ver, null, "/", null);
            if ( !browserInfo.isSupported ) {
                BrowserAgent.logger.warn("BrowserAgent.main: Unsupported browser. Disabling Browser Agent ...");
                return;
            }
        }
        // Calculate client server gap time server time cookie
        var serverTimeCookie = BrowserAgent.cookieUtils.getRawCookie(BrowserAgent.cookieUtils.cookies.SERVERTIME);
        if ( serverTimeCookie ) {
            BrowserAgent.globals.gapTimeInMillis = BrowserAgent.globals.baStartTime - serverTimeCookie;
            BrowserAgent.cookieUtils.setRawCookie(BrowserAgent.cookieUtils.cookies.GAPTIME,
                                                  Math.ceil(BrowserAgent.globals.gapTimeInMillis / 1000), null,
                                                  "/", null);
            BrowserAgent.logger.info("BrowserAgent.main: Client Server gap time is " +
                                     BrowserAgent.globals.gapTimeInMillis + " ms");
        }
        // Extract the App Information - profileUrl, tenantId, appId and appKey
        if ( !BrowserAgent.configUtils.extractAppInfo() ) {
            BrowserAgent.logger.warn("BrowserAgent.main: Disabling Browser Agent ...");
            return;
        }
        // Get app profile
        var xhr = new XMLHttpRequest();
        if ( xhr ) {
            // Do a Synchronous GET
            xhr.open('GET', BrowserAgent.globals.profileURL, false);
            xhr.onreadystatechange = function () {
                if ( xhr.readyState === this.DONE && xhr.status === 200 ) {
                    var appProfile = null;
                    try { // JSON.parse() will throw error if input is invalid
                        appProfile = JSON.parse(xhr.responseText);
                    } catch ( e ) {
                        BrowserAgent.logger.error("BrowserAgent.main: Invalid app profile - " + e.message +
                                                  ". Disabling Browser Agent...");
                        return;
                    }
                    if ( !BrowserAgent.configUtils.processAppProfile(appProfile) ) {
                        return;
                    }
                    // Check if BA is enabled
                    if ( BrowserAgent.globals.configs.BROWSERAGENTENABLED === false ) {
                        // False or invalid values
                        BrowserAgent.logger.info("BrowserAgent.main: Browser Agent is DISABLED.");
                        return;
                    }
                    // Check if collector url is valid
                    if ( typeof BrowserAgent.globals.configs.COLLECTORURL !== 'string' ||
                         BrowserAgent.globals.configs.COLLECTORURL === "" ) {
                        BrowserAgent.logger.error("BrowserAgent.main: Invalid collector URL. Disabling Browser Agent...");
                        return;
                    }
                    // Start Browser Agent instrumentation
                    BrowserAgent.cookieUtils.init();
                    BrowserAgent.storageUtils.init();
                    BrowserAgent.browserUtils.init();
                    BrowserAgent.funcUtils.init();
                    BrowserAgent.errorUtils.init();
                    BrowserAgent.evtUtils.init();
                    BrowserAgent.globals.init();
                    // Add Event listener to unload events of a page for dispatching page think time
                    // on the capturing phase
                    // Register for beforeunload rather than unload.  The browser close process has already
                    // started when unload is called and on Edge browser this can cause ajax request to
                    // be aborted in the send process.
                    // Safari doesnt support beforeunload, so register for pagehide.
                    window.addEventListener("beforeunload", BrowserAgent.pageUtils.tTimeHandler, true);
                    window.addEventListener("pagehide", BrowserAgent.pageUtils.tTimeHandler, true);
                    BrowserAgent.pageUtils.init();

                    // EXTENSION POINT for custom init
                    if ( typeof BrowserAgentExtension !== "undefined" ) {
                        BrowserAgentExtension.init();
                    }

                    BrowserAgent.globals.harvestIntervalId = setInterval(BrowserAgent.evtUtils.harvestEvts,
                                                                         BrowserAgent.globals.configs.METRICFREQUENCY);
                }
            };
            xhr.send();
        }
    };

    // Modern browsers try to prefetch, preload and even pre-render web pages in order to optimize user experience
    // Pre-load => Fetch the web page prior to actual user visit and load whilst user visit
    // Pre-render => Fetch the web page prior to actual user visit and render it in the background and do not
    //               reload whilst user visit
    // TODO: In either case, BA will detect if a web page is in pre-render state. If so, set a flag.
    if ( document.visibilityState === 'prerender' ) {
        BrowserAgent.logger.warn("Web page in pre-render state.");
    }

    // This is the entry point to BA
    BrowserAgent.main();
} catch
    ( e ) {
    if ( window.console && typeof window.console === 'object' ) {
        window.console.log(new Date() + " [CA Browser Agent]: [ERROR] " + e.message);
    }
}
