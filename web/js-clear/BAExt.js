/**
 * CA Wily Introscope(R) Version @@2.0.0.3@@ Build @@4@@
 * @@Copyright (c) 2017 CA. All Rights Reserved.@@
 * @@Introscope(R) is a registered trademark of CA.@@
 */
try {
    var BrowserAgentExtension = {
        init : function () {

            /**
             * ADD YOUR OWN CODE HERE
             */

        },
        /**
         * Adds JS functions to be instrumented for JS function metrics.
         */
        extAddJSFuncToInstrument : function () {
            /**
             * Add JS Functions here to instrument using BrowserAgentExtension.addJSFuncToInstrument( functionName,
             * preTracerList, postTracerList ) Note: If the JS function to be instrumented is a member function inside
             * a JS object, you may need to add the keyword 'prototype'.
             *
             * preTracerList is an array of JavaScript objects, where each object describes a JavaScript function
             * to be invoked before the invocation of the instrumented function (functionName)
             *
             * postTracerList is an array of JavaScript objects, where each object describes a JavaScript function to
             * be invoked after the invocation of the instrumented function (functionName)
             *
             * Here is the JavaScript object format for preTracerList and postTracerList
             * {
             *   name: <Name of the JavaScript function to be invoked before the invocation of the instrumented
             *          function>,
             *   args: [<arg_1>, <arg_2>, <arg_3>, ....]
             * }
             *
             *
             * Example:
             * Calculate User Think time between "Add Items to Cart" and "CheckOut"
             * Assume on a page the "Add to Cart" button invokes addItemToCart(itemID) function and "CheckOut" button
             * invokes checkOut(cartID) function.
             *
             * Step 1: Have a place to store raw data
             * var myOwnAccumulator = { cartAddTimes : [], checkOutTime : null};
             *
             * Step 2: Write a preTracer for "addItemToCart" JS method
             * Let’s call this preTracer 'addItemToCartPreTracer' and nest it under the BrowserAgentExtension object.
             * BrowserAgentExtension.addItemToCartPreTracer = function() {
             *  // Browser Agent exposes an object in which a tracer can store and retrieve data at a later point.
             *  var stateObj;
             *  // Browser Agent recommends that you wrap the tracer code in its own try, catch block to avoid early
             *  // termination due to runtime errors.
             *  try {
             *      // The last argument to a tracer is always the BA state object.
             *      stateObj = arguments[arguments.length - 1];
             *      // Get the current time and store it
             *      myOwnAccumulator["cartAddTimes"].push(new Date().getTime());
             *  } catch ( e ) {
             *      BrowserAgent.logger.error("addItemPre (" + stateObj.origFunctionName + "): " + e.message);
             *  }
             * }
             *
             * Step 3: Write a postTracer for "checkOut" JS method
             * Let’s call this postTracer 'checkOutPostTracer' and nest it under the BrowserAgentExtension object.
             * Note: This postTracer also pushes data with the addExtensionJSONObject API
             * BrowserAgentExtension.checkOutPostTracer = function() {
             *  // Again, Browser Agent exposes an object in which a tracer can store and retrieve data at a later
             *  // point.
             *  var stateObj;
             *  // Again, Browser Agent recommends that you wrap the tracer code in its own try, catch block to avoid
             *  // early termination due to runtime errors.
             *  try {
             *      // Again, the last argument to a tracer is always the BA state object.
             *      stateObj = arguments[arguments.length - 1];
             *      // Get the current time and store it
             *      myOwnAccumulator["checkOutTime"] = new Date().getTime();
             *
             *      if(myOwnAccumulator["cartAddTimes"].length < 1) { return; }
             *      // Now, do the checkout duration calculation
             *      var checkoutTime = myOwnAccumulator["checkOutTime"] - myOwnAccumulator["cartAddTimes"][0];
             *      // Tell BA to report the data
             *      var metricList = [];
             *      // This is the context in which the data will be reported in APM Browser Agent
             *      var metricPath = BrowserAgent.globals.currPagePtr.pageMetricPath + BrowserAgent.globals.pipeChar +
             *                      "MISC";
             *      // Use BrowserAgentExtension.createCustomMetric API to create a new APM Browser Agent metric and
             *      add it to a list of custom metrics
             *      metricList.push(BrowserAgentExtension.createCustomMetric("CheckOut Time", "ms", 0, checkoutTime,
             *                                                               metricPath));
             *      // Use the BrowserAgentExtension.addExtensionJSONObject to construct a JSON payload for this custom
             *      // metric
             *      BrowserAgentExtension.addExtensionJSONObject(metricList);
             *      // Clear out the data; we don't want to report the same data twice
             *      myOwnAccumulator["cartAddTimes"] = [];
             *      myOwnAccumulator["checkOutTime"] = null;
             *  } catch ( e ) {
             *      BrowserAgent.logger.error("checkOutPost (" + stateObj.origFunctionName + "): " + e.message);
             *  }
             * }
             * Step 4: Use the addJSFuncToInstrument API to attach the pre and post tracers from Step 2 and 3
             * // Attach the "BrowserAgentExtension.addItemToCartPreTracer" as a PreTracer to the addItemToCart JS
             * method BrowserAgentExtension.addJSFuncToInstrument("addItemToCart",
             *                                             [{ name: "BrowserAgentExtension.addItemToCartPreTracer"}]);
             * // Attach the "BrowserAgentExtension.checkOutPostTracer" as a PostTracer to the checkOutItem JS method
             * BrowserAgentExtension.addJSFuncToInstrument("checkOutItem", null,
             *                                             [{ name: "BrowserAgentExtension.checkOutPostTracer"}]);
             **/
        },
        /**
         * Adds custom page load metrics for each page.
         * @returns {Array}
         */
        extAddCustomPageMetric : function () {
            /**
             * Step 1
             * Do your work to collect metrics.
             *
             * Step 2
             * Add collected metrics for harvesting using BrowserAgentExtension.addCustomPageMetric(name, unit, type,
             * value).
             * Metric path is not needed here since it will use the page metric path by default.
             *
             * Example 1: Report DOM Depth of a Web Page
             * Note: This is not the actual implementation to calculate the DOM depth of a web page, but
             * just an example with JS random number generator.
             *
             * function getRandomNumberOneToFive() { return Math.floor(Math.random() * (5 - 1)) + 1; }
             * var domDepth = getRandomNumberOneToFive();
             * BrowserAgentExtension.addCustomPageMetric("DOM Depth", null, 0, domDepth);
             *
             * Example 2: Report JS Heap Usage in Bytes
             * Note: The window.performance.memory object is only available in Google Chrome.
             *
             * function getHeapSize() { return window.performance.memory.usedJSHeapSize; }
             * var jsHeapUsage = getHeapSize();
             * BrowserAgentExtension.addCustomPageMetric("Heap Usage", "bytes", 0, jsHeapUsage);
             */
        },
        /**
         * Adds custom JS function metrics for each JS function.
         * @returns {Array} - array of metrics
         */
        extAddCustomJSFuncMetric : function () {
            /**
             * Step 1
             * Do your work to collect metrics.
             *
             * Step 2
             * Add collected metrics for harvesting using BrowserAgentExtension.addCustomJSFuncMetric(name, unit, type,
             * value).
             * Metric path is not needed here since it will use the page metric path by default.
             *
             * Example: Report Argument Length of a JavaScript Method
             * Note: This is not the actual implementation to calculate the argument length of a JS method, but just
             * an example with JS random number generator.
             *
             * function getRandomNumberOneToFive() { return Math.floor(Math.random() * (5 - 1)) + 1; };
             * var argLength = getRandomNumberOneToFive();
             * BrowserAgentExtension.addCustomJSFuncMetric("Argument Length", null, 0, argLength);
             */
        },
        /**
         * Adds custom Ajax metrics for each Ajax call.
         * @returns {Array}
         */
        extAddCustomAjaxMetric : function () {
            /**
             * Step 1
             * Do your work to collect metrics.
             *
             * Step 2
             * Add collected metrics for harvesting using BrowserAgentExtension.addCustomAjaxMetric(name, unit, type,
             * value).
             * Metric path is not needed here since it will use the corresponding Ajax metric path by default.
             *
             * Example: Report Content Length in Bytes
             * Note: This is not the actual implementation to calculate the Content Length of an HTTP response, but
             * just an example with JS random number generator
             *
             * function getRandomNumber1Kto4K() { return Math.floor(Math.random() * (4096 - 1024)) + 1024; };
             * var contentLength = getRandomNumber1Kto4K();
             * BrowserAgentExtension.addCustomAjaxMetric("Content Length", "bytes", 0, contentLength);
             */
        },
        /**
         * Adds custom optional transaction trace properties for each transaction trace.
         * @returns {Array}
         */
        extAddCustomOptionalProperty : function () {
            /**
             * Add Transaction Trace Properties here using BrowserAgentExtension.addCustomOptionalProperty(name, value,
             * description).
             * Note: property description is optional.
             *
             * Example: Report Previous Page URL in the Trace Components
             *
             * function getPreviousPage() {
             *   var referrer = document.referrer;
             *   if ( !referrer ) { referrer = "N/A"; }
             *   return referrer;
             * }
             * var prevPageURL = getPreviousPage();
             * BrowserAgentExtension.addCustomOptionalProperty("Previous Page", prevPageURL);
             **/
        },
        /**
         * Name formatter allows you to change/group metrics by giving flexibility to change the metric path, name,
         * unit, aggregator type and value before creating the final metric.
         * Note: It's not recommended to change metric type and value. Instead, you can add custom metrics.
         * @param path - metric path as a string
         * @param name - metric name as a string
         * @param unit - metric unit as null or a string
         * @param type - metric accumulator type as a number enum -
         *        0 : INT_LONG_DURATION (These metrics are aggregated over time by taking the average of the values
         *        per interval)
         *        1 : LONG_INTERVAL_COUNTER (These metrics are aggregated over time by summing the values per interval)
         * @param value - metric value as a number
         * @returns {*|{name, unit, type, value, path}|{name: *, unit: *, type: *, value: *, path: *}}
         */
        extNameFormatter : function ( path, name, unit, type, value ) {
            /**
             *  Step 1
             *  Do your work to format the input metric.
             *  Note: It's not recommended to change metric type and value. Instead, you can add custom metrics.
             *  Metric path can be formatted URL or Business Transaction if matched on Agent.
             *
             *  Step 2
             *  Return a new metric with formatted metric info using
             *  BrowserAgentExtension.createCustomMetric(name, unit, type, value, path).
             *
             *  EXAMPLE 1: Rename Metrics
             *  Change all metrics that has metric name "Invocation Count Per Interval" to "Country Visit Count" -
             *
             *  if (name === "Invocation Count Per Interval") {
             *      name = "Country Visit Count";
             *  }
             *  return BrowserAgentExtension.createCustomMetric(name, unit, type, value, path);
             *
             *  EXAMPLE 2: Aggregate Metrics from Dynamic URLs
             *  For all metrics that have paths containing "country_#" such as:
             *  localhost/5080|/worldpop|AJAX Call|localhost/5080|/country_1/country.json
             *  localhost/5080|/worldpop|AJAX Call|localhost/5080|/country_2/country.json
             *  localhost/5080|/worldpop|AJAX Call|localhost/5080|/country_3/country.json
             *
             *  Combine all of the "localhost/5080|/worldpop|AJAX Call|localhost/5080|/country_#/country.json"
             *  into "localhost/5080|/worldpop|AJAX Call|localhost/5080|/country.json".
             *
             *  path = path.replace(/country_\d+\//g, "");
             *  return BrowserAgentExtension.createCustomMetric(name, unit, type, value, path);
             */
        },
        // Stubs for APM Extension APIs
        /**
         * Adds JavaScript function to be instrumented for JS function metrics.
         * @param functionName - JavaScript function name as a string. If the JS function to be instrumented is a
         *     member function inside a JS object, you may need to add the keyword prototype
         * @param preTracerList - An array of Javascript functions whose invocation precedes the function to be
         *     instrumented
         * @param postTracerList - An array of Javascript functions whose invocation succeeds the function to be
         *     instrumented
         */
        addJSFuncToInstrument : function ( functionName, preTracerList, postTracerList ) {},
        /**
         * Creates a custom page metric and adds it to extCustomPageMetricList.
         * @param name - metric name as a string
         * @param unit - metric unit as null or a string
         * @param type - metric accumulator type as a number enum -
         *        0 : INT_LONG_DURATION (These metrics are aggregated over time by taking the average of the values
         *        per interval)
         *        1 : LONG_INTERVAL_COUNTER (These metrics are aggregated over time by summing the values per interval)
         * @param value - metric value as a number
         */
        addCustomPageMetric : function ( name, unit, type, value ) {},
        /**
         * Creates a custom JS function metric and adds it to extCustomJSFuncMetricList.
         * @param name - metric name as a string
         * @param unit - metric unit as null or a string
         * @param type - metric accumulator type as a number enum -
         *        0 : INT_LONG_DURATION (These metrics are aggregated over time by taking the average of the values
         *        per interval)
         *        1 : LONG_INTERVAL_COUNTER (These metrics are aggregated over time by summing the values per interval)
         * @param value - metric value as a number
         */
        addCustomJSFuncMetric : function ( name, unit, type, value ) {},
        /**
         * Creates a custom Ajax metric and adds it to extCustomAjaxMetricList.
         * @param name - metric name as a string
         * @param unit - metric unit as null or a string
         * @param type - metric accumulator type as a number enum -
         *        0 : INT_LONG_DURATION (These metrics are aggregated over time by taking the average of the values
         *        per interval)
         *        1 : LONG_INTERVAL_COUNTER (These metrics are aggregated over time by summing the values per interval)
         * @param value - metric value as a number
         */
        addCustomAjaxMetric : function ( name, unit, type, value ) {},
        /**
         * Creates a custom optional transaction trace property and adds it to extCustomOptionalPropertyList.
         * @param name - name of property as a string
         * @param value - value of property as a string
         * @param description - description of property. Optional.
         * @returns {{name: *, value: *, description: *}}
         */
        addCustomOptionalProperty : function ( name, value, description ) {},
        /**
         * Creates an extension JSON object that follows the Browser Agent JSON schema
         * @param metricList - a list of metrics
         */
        addExtensionJSONObject : function ( metricList ) {},
        /**
         * Creates a custom metric without validation.
         * @param name - metric name as a string
         * @param unit - metric unit as null or a string
         * @param type - metric accumulator type as a number enum -
         *        0 : INT_LONG_DURATION (These metrics are aggregated over time by taking the average of the values
         *        per interval)
         *        1 : LONG_INTERVAL_COUNTER (These metrics are aggregated over time by summing the values per interval)
         * @param value - metric value as a number
         * @param path - metric path as a string. May be optional.
         * @returns {{name: *, unit: *, type: *, value: *, path: *}}
         */
        createCustomMetric : function ( name, unit, type, value, path ) {},

        // Stubs for AXA Extension APIs
        /**
         * Logs a text metric
         * @param evt
         * Usage : BrowserAgentExtension.logTextMetric({"key" : "key", "value" : "value",
         *                                              "attributes" : { "k" : "v" } });
         */
        logTextMetric : function ( evt ) {},
        /**
         * Logs a numeric metric
         * @param evt
         * Usage : BrowserAgentExtension.logNumericMetric({"key" : "key", "value": 99.99,
         *                                                 "attributes" : { "k" : "v" } });
         */
        logNumericMetric : function ( evt ) {},
        /**
         * Sets the location of the browser. Collects the country code and zip code or latitude and longitude of the
         * user location as set by application.
         * @param location
         * Usage: BrowserAgentExtension.setCustomerLocation({"zipCode" : "95051", "countryCode" : "US",
         *                                                   "latitude" : "122.222", "longitude" : "33",
         *                                                   "attributes" : { "k" : "v" } });
         */
        setCustomerLocation : function ( location ) {},
        /**
         * Logs a session level information
         * @param evt
         * Usage: BrowserAgentExtension.setSessionAttribute({"type" : "string", "key" :
         *                                              "sessionEventKey", "value" : "sessionEventValue" });
         * Note: "type" can be a String or a Number
         */
        setSessionAttribute : function ( evt ) {},
        /**
         * Starts a new application transaction that bounds all the subsequent events
         * @param evt
         * Usage: BrowserAgentExtension.startApplicationTransaction({"transactionName" : "itemAddedToShoppingCart",
         *                                                           "serviceName" : "CheckoutScreen",
         *                                                           "attributes" : { "k" : "v"}});
         */
        startApplicationTransaction : function ( evt ) {},
        /**
         * Stops the application transaction
         * @param evt
         * Usage: BrowserAgentExtension.stopApplicationTransaction({"transactionName" : "itemAddedToShoppingCart",
         *                                                          "serviceName" : "CheckoutScreen",
         *                                                          "failure" : "Reason for failure",
         *                                                          "attributes" : { "k" : "v"}});
         */
        stopApplicationTransaction : function ( evt ) {},
        /**
         * Logs a network event
         * @param evt
         * Usage: BrowserAgentExtension.logNetworkEvent({ "url" : "http://ck.com", "status" : 200, "inbytes" : 33,
         *                                                "outbytes" : 33, "time" : 344, "attributes" : { "k" : "v"}});
         */
        logNetworkEvent : function ( evt ) {},
        /**
         * Sets customerId,usually post login of application - Get unique identifier such as username or userId to set
         * as customerId.
         * @param evt
         * Usage: BrowserAgentExtension.setCustomerId({"customerId" : "UserName" , "attributes" : { "k" : "v" } });
         */
        setCustomerId : function ( evt ) {}
    };
} catch ( e ) {
    if ( window.BrowserAgent && BrowserAgent.logger ) {
        BrowserAgent.logger.log("BrowserAgentExtensionError: " + e.message);
    } else if ( window && window.console ) {
        window.console.log("BrowserAgentExtensionError: " + e.message);
    }
}
