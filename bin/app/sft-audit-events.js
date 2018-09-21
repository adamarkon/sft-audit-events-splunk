(function() {
  var url = require('url');
  var util = require('util');
  var crypto = require('crypto');
  var path = require('path');
  var fs = require('fs');

  var request = require('request');
  var async = require('async');

  var splunkjs = require("splunk-sdk");
  var ModularInputs = splunkjs.ModularInputs;
  var Logger = ModularInputs.Logger;
  var Event = ModularInputs.Event;
  var Scheme = ModularInputs.Scheme;
  var Argument = ModularInputs.Argument;

  var INPUT_NAME = 'sft-audit-events';

  /**
   * The ScaleftInput object does most of the work for us.
   *  * Authentication
   *  * Polling
   *  * Event submission
   *  * Validation
   *  * State management
   */
  var ScaleftInput = function(teamName, instanceAddress, clientKey, clientSecret, checkpointDir) {
    this.token = "";
    this.tokenExpiration = 0;
    this.teamName = teamName;
    this.clientKey = clientKey;
    this.clientSecret = clientSecret;
    this.checkPointDir = checkpointDir;
    this.lastIndexTime = 0;

    if (instanceAddress.lastIndexOf('/') === instanceAddress.length - 1) {
      this.instanceAddr = instanceAddress.slice(0, -1);
    } else {
      this.instanceAddr = instanceAddress;
    }
  };

  /**
   * Checks to see if the auth token we have is valid. If it is not, attempt to get a new auth token.
   */
  ScaleftInput.prototype.refreshToken = function(callback) {
    var self = this;

    if (Date.now() < this.tokenExpiration) {
      callback();
      return;
    }

    Logger.info(INPUT_NAME, "Token is expired. Refreshing.");

    request({
      uri: this.getRequestUri('/service_token'),
      method: 'POST',
      json: true,
      body: {
        key_id: this.clientKey,
        key_secret: this.clientSecret
      }
    }, function(err, msg, body) {
      if (err) {
        Logger.error(INPUT_NAME, 'Error getting token: ' + err.msg);
        callback(err);
        return;
      }

      self.token = body.bearer_token;
      self.tokenExpiration = Date.now() + 60 * 60 * 1000; // The token expires in 1 hour.
      callback();
    });
  };

  /**
   * Helper function for returning the base URI for an API request.
   */
  ScaleftInput.prototype.getRequestUri = function(path) {
    return this.instanceAddr + util.format('/v1/teams/%s%s', this.teamName, path);
  };

  /**
   * Return a set of audit events from the ScaleFT API.
   * It follows this workflow:
   *  * Make sure we have a valid auth token from the ScaleFT API.
   *  * Makes a request to the ScaleFT API for the last 100 audit events.
   */
  ScaleftInput.prototype.getEvents = function(callback) {
    var self = this;

    async.auto({
      refreshToken: this.refreshToken.bind(this),
      getEvents: ['refreshToken', function(results, callback) {
        var qs = {
          descending: '1'
        };

        if (self.lastIndexTime) {
          qs.after_time = self.lastIndexTime
        }

        request({
          uri: self.getRequestUri('/auditsV2'),
          qs: qs,
          method: 'GET',
          json: true,
          auth: {
            bearer: self.token
          }
        }, function(err, msg, body) {
          if (err) {
            Logger.error(INPUT_NAME, 'Error retrieving audit events: ' + err);
            callback(err);
            return;
          }
          callback(null, body);
        });
      }]
    }, function(err, results) {
      if (err) {
        callback(err);
        return;
      }

      callback(null, results.getEvents);
    });
  };

  /**
   * Helper function that returns a readable name for each actor type.
   */
  ScaleftInput.prototype.getActorType = function(actorType) {
    switch (actorType.toUpperCase()) {
      case 'T':
        return 'team';
      case 'U':
        return 'user';
      case 'I':
        return 'instance';
      case 'D':
        return 'device';
      case 'DT':
        return 'device type';
      default:
        return actorType;
    }
  };

  /**
   * A helper function that formats events.
   */
  ScaleftInput.prototype.formatEvent = function(ev, relatedObjects) {
    var ret = {
          id: ev.id,
          timestamp: ev.timestamp
        }
        rObjs = {};

    Object.keys(ev.details).forEach(function(detail) {
      if (relatedObjects.hasOwnProperty(ev.details[detail])) {
        var rObj = relatedObjects[ev.details[detail]],
            objList = rObjs[rObj.type] || [];
        objList.push(rObj.object);
        rObjs[rObj.type] = objList;
      } else if (ev.details[detail] !== '') {
        ret[detail] = ev.details[detail];
      }
    });


    if (Object.keys(rObjs).length !== 0) {
      ret['related_objects'] = rObjs;
    }

    return ret;
  };

  /**
   * Returns the path to the checkpoint file.
   */
  ScaleftInput.prototype.getCheckpointPath = function() {
    var shasum = crypto.createHash('sha1');

    shasum.update(util.format('%s-%s', this.teamName, this.instanceAddr));

    return path.join(this.checkPointDir, INPUT_NAME, shasum.digest('hex'));
  };

  /**
   * Saves the provided timestamp to the checkpoint file.
   */
  ScaleftInput.prototype.saveCheckpoint = function(timestamp) {
    Logger.info(INPUT_NAME, "saving check point")
    fs.writeFileSync(this.getCheckpointPath(), timestamp.toString());
  };

  /**
   * Returns a timestamp loaded from the checkpoint file.
   * If the checkpoint file can't be read or is invalid, return false.
   */
  ScaleftInput.prototype.loadCheckpoint = function() {
    var ts = null;
    try {
      var ts = new Date(fs.readFileSync(this.getCheckpointPath()));
    } catch (e) {
      return false
    }

    if (isNaN(ts.getTime())) {
      return false
    }

    return ts;
  };

  /**
   * Returns the scheme for the input's configuration.
   */
  exports.getScheme = function () {
    var scheme = new Scheme("ScaleFT Audit Event Input")

    scheme.description = "A modular input that retrieves audit events from ScaleFT's API.";
    scheme.useExternalValidation = true;
    scheme.useSingleInstance = false;

    scheme.args = [
      new Argument({
        name: "team_name",
        dataType:  Argument.dataTypeString,
        description: "The ScaleFT team name to receive audit logs from.",
        requiredOnCreate: true,
        requiredOnEdit: true
      }),

      new Argument({
        name: "instance_address",
        dataType: Argument.dataTypeString,
        description: "The address to the instance of ScaleFT to use.",
        requiredOnCreate: true,
        requiredOnEdit: true
      }),

      new Argument({
        name: "polling_interval",
        dataType: Argument.dataTypeNumber,
        description: "The number of seconds to wait before polling for new audit events. Defaults to 60.",
        requiredOnCreate: true,
        requiredOnEdit: true
      }),

      new Argument({
        name: "client_key",
        dataType: Argument.dataTypeString,
        description: "The client key for your ScaleFT service user.",
        requiredOnCreate: true,
        requiredOnEdit: true
      }),

      new Argument({
        name: "client_secret",
        dataType: Argument.dataTypeString,
        description: "The client secret for your ScaleFT service user.",
        requiredOnCreate: true,
        requiredOnEdit: true
      }),

      new Argument({
        name: "checkpoint_dir",
        dataType: Argument.dataTypeString,
        description: "The path to a directory to hold modular input state. Typically $SPLUNK_DB/modinputs/",
        requiredOnCreate: true,
        requiredOnEdit: true
      })
    ];

    return scheme;
  };

  /**
   * Validation for config settings.
   */
  exports.validateInput = function(definition, done) {
    var teamName = definition.parameters.team_name.toString().toLowerCase(),
        instanceAddr = definition.parameters.instance_address.toString(),
        client_key = definition.parameters.client_key.toString(),
        interval = parseInt(definition.parameters.polling_interval, 10),
        teamNameRegex = /^[\w\-_.]+$/;

    if (!teamName.match(teamNameRegex)) {
      done(new Error("Team names must match regular expression ^[\w\-_.]+$"));
      return;
    }

    if (client_key.length !== 36) {
      done(new Error("The client key does not appear to be valid."));
      return;
    }

    if (interval < 30) {
      done(new Error("The minimum polling interval is 30 seconds."));
      return;
    }

    var parsedInstanceAddr = url.parse(instanceAddr);

    if (!parsedInstanceAddr.hostname) {
      done(new Error("Instance address does not appear to be a valid URL."));
      return;
    }

    if (parsedInstanceAddr.protocol !== 'https:') {
      done(new Error("Instance address is not an https url."));
      return;
    }

    done();
  };

  /**
   * This method actually retrieves audit events and inputs them into splunk.
   */
  exports.streamEvents = function(name, singleInput, eventWriter, done) {
    var pollingInterval = parseInt(singleInput.polling_interval, 10),
        sftInput = new ScaleftInput(
          singleInput.team_name,
          singleInput.instance_address,
          singleInput.client_key,
          singleInput.client_secret,
          singleInput.checkpoint_dir
        );

    var checkpoint = sftInput.loadCheckpoint();

    if (checkpoint) {
      Logger.info(INPUT_NAME, "Loaded checkpoint data: " + checkpoint);
      sftInput.lastIndexTime = checkpoint;
    }

    (function pollEvents() {
      Logger.info(INPUT_NAME, "Polling for new sft audit events.");

      async.auto({
        getEvents: sftInput.getEvents.bind(sftInput),

        emitToSplunk: ['getEvents', function (results, callback) {
          var evts = results.getEvents.list,
              relatedObjects = results.getEvents.related_objects,
              indexTime = null;

          if (!evts) {
            callback();
            return;
          }

          evts.forEach(function (ev) {
            var evDate = new Date(ev.timestamp);

            if (!indexTime) {
              indexTime = evDate;
            }

            if (evDate <= sftInput.lastIndexTime) {
              return;
            }

            var newEv = new Event({
              stanza: name,
              data: sftInput.formatEvent(ev, relatedObjects)
            });

            try {
              eventWriter.writeEvent(newEv);
            } catch (e) {
              Logger.error(name, e.message);
            }
          });

          sftInput.lastIndexTime = indexTime;
          sftInput.saveCheckpoint(sftInput.lastIndexTime);
          callback();
        }]
      }, function (err) {
        if (err) {
          Logger.error(INPUT_NAME, "Error while polling events. Sleeping for 1 minute.");
        }
        setTimeout(pollEvents, pollingInterval * 1000);
      });
    })();
  };

  ModularInputs.execute(exports, module);
})();
