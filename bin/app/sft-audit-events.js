(function() {
  var url = require('url');
  var util = require('util');
  var crypto = require('crypto');
  var path = require('path');
  var fs = require('fs');
  var readline = require('readline');

  var request = require('request');
  var async = require('async');
  var parseLinks = require('parse-link-header');

  var splunkjs = require("splunk-sdk");
  var ModularInputs = splunkjs.ModularInputs;
  var Logger = ModularInputs.Logger;
  var Event = ModularInputs.Event;
  var Scheme = ModularInputs.Scheme;
  var Argument = ModularInputs.Argument;

  var INPUT_NAME = 'sft-audits';
  var INPUT_KIND = 'sft-audit-events';
  var SECRET_MASK = '******';

  /**
   * The ScaleftInput object does most of the work for us.
   *  * Authentication
   *  * Polling
   *  * Event submission
   *  * Validation
   *  * State management
   */
  var ScaleftInput = function(teamName, instanceAddress, clientKey, clientSecret) {
    this.token = "";
    this.tokenExpiration = 0;
    this.teamName = teamName;
    this.clientKey = clientKey;
    this.clientSecret = clientSecret;
    this.lastIndexOffset = "";
    this.api_version = 2;

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

    Logger.info(INPUT_KIND, "Token is expired. Refreshing.");

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
        Logger.error(INPUT_KIND, 'Error getting token: ' + err.msg);
        callback(err);
        return;
      }

      if (msg.statusCode !== 200) {
        Logger.error(INPUT_KIND, 'Unexpected status code: ' + msg.statusCode);
        if (body) {
          Logger.error(INPUT_KIND, "Error response: " + JSON.stringify(body))
        }
        callback(new Error("unexpected status code"));
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
  ScaleftInput.prototype.getEvents = function(eventWriter, callback) {
    var self = this;

    async.auto({
      refreshToken: this.refreshToken.bind(this),
      getEvents: ['refreshToken', function(results, callback) {
        var qs = {},
            initialRequest = true,
            gettingLatest = false;

        Logger.info(INPUT_KIND, "Last offset: '" + self.lastIndexOffset + "'");

        if (self.lastIndexOffset !== "") {
          qs.offset = self.lastIndexOffset;
        } else {
          qs.count = 1;
          qs.descending = true;
          gettingLatest = true;
        }

        var uri = self.getRequestUri('/auditsV2');
        var urls = [uri];

        async.until(function done() {
          return urls.length === 0;
        }, function(callback) {
          var current = urls.shift();

          Logger.info(INPUT_KIND, "Grabbing audits page with: " + current);

          var urlOpts = {
            uri: current,
            method: 'GET',
            json: true,
            auth: {
              bearer: self.token
            }
          };

          if (initialRequest) {
            urlOpts.qs = qs;
            initialRequest = false;
          }

          request(urlOpts, function (err, msg, body) {
            if (err) {
              Logger.error(INPUT_KIND, 'Error retrieving audit events: ' + err);
              callback(err);
              return;
            }

            if (msg.statusCode !== 200) {
              Logger.error(INPUT_KIND, 'Unexpected status code: ' + msg.statusCode);
              if (body) {
                Logger.error(INPUT_KIND, "Error response: " + JSON.stringify(body))
              }
              callback(new Error("unexpected status code"));
              return;
            }

            if (!gettingLatest) {
              var links = parseLinks(msg.headers.link);
              if (links && links.next && links.next.url) {
                urls.push(links.next.url);
              }
            }

            if (body) {
              if (!body.list || !body.related_objects) {
                callback(new Error("malformed response, dying."));
                return
              }

              var indexOffset = (body.list[body.list.length - 1] && body.list[body.list.length - 1].id) || "";

              body.list.forEach(function(ev) {
                var newEv = new Event({
                  stanza: INPUT_KIND,
                  data: self.formatEvent(ev, body.related_objects)
                });

                try {
                  eventWriter.writeEvent(newEv);
                } catch (e) {
                  Logger.error(INPUT_KIND, e.message);
                }
              });

              if (indexOffset !== "") {
                Logger.info(INPUT_KIND, "Saving checkpoint: " + indexOffset);
                self.lastIndexOffset = indexOffset;
                self.saveCheckpoint(self.lastIndexOffset);
              }

              Logger.info(INPUT_KIND, "Got events: " + body.list.length);
            }

            callback(null);
          });
        }, function(err) {
          if (err) {
            callback(err);
            return;
          }

          callback();
        });
      }]
    }, function(err, results) {
      if (err) {
        Logger.error(INPUT_KIND, 'Error retrieving audit events: ' + err);
        callback(err);
        return;
      }

      callback();
    });
  };

  /**
   * A helper function that formats events.
   */
  ScaleftInput.prototype.formatEvent = function(ev, relatedObjects) {
    var ret = {
          id: ev.id,
          timestamp: ev.timestamp
        },
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

    shasum.update(util.format('%s-%s-%d', this.teamName, this.instanceAddr, this.api_version));

    return path.join(process.env["SPLUNK_DB"], "modinputs", INPUT_KIND, shasum.digest('hex'));
  };

  /**
   * Saves the provided timestamp to the checkpoint file.
   */
  ScaleftInput.prototype.saveCheckpoint = function(timestamp) {
    Logger.info(INPUT_KIND, "saving check point");
    fs.writeFileSync(this.getCheckpointPath(), timestamp.toString());
  };

  /**
   * Returns a timestamp loaded from the checkpoint file.
   * If the checkpoint file can't be read or is invalid, return false.
   */
  ScaleftInput.prototype.loadCheckpoint = function() {
    var offset = "";

    try {
      offset = fs.readFileSync(this.getCheckpointPath());
    } catch (e) {
      return false;
    }

    return offset;
  };

  /**
   * Returns the scheme for the input's configuration.
   */
  exports.getScheme = function () {
    var scheme = new Scheme("ScaleFT Audit Event Input");

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

  exports.service = function() {
	  if (this._service) {
		  return this._service;
	  }

		if (!this._inputDefinition) {
		  return null;
		}

		var splunkdURI = this._inputDefinition.metadata["server_uri"];
		var sessionKey = this._inputDefinition.metadata["session_key"];

		var urlParts = url.parse(splunkdURI);

		// urlParts.protocol will have a trailing colon; remove it.
		var scheme = urlParts.protocol.replace(":", "");
		var splunkdHost = urlParts.hostname;
		var splunkdPort = urlParts.port;

		this._service = new splunkjs.Service({
				scheme: scheme,
				host: splunkdHost,
				port: splunkdPort,
				token: sessionKey
		});

		return this._service;
  };

	exports.encrypt = function(key, val, callback) {
    var s = this.service();
    var storagePasswords = s.storagePasswords();

    async.auto({
      fetch: function(callback) {
        storagePasswords.fetch(callback);
      },
      rm: ['fetch', function(results, callback) {
        var matchingPass;

        results.fetch.list().forEach(function(pass) {
          if (matchingPass) {
            return;
          }
          if (pass._properties.username === key) {
            matchingPass = pass;
          }
        });

        if (matchingPass) {
          matchingPass.remove(callback);
          return;
        }

        callback();
      }],
      create: ['rm', function(results, callback) {
        storagePasswords.create({
          name: key,
          password: val
        }, callback);
      }],
    }, function(err, results) {
      if (err) {
        Logger.error(INPUT_KIND, "error encrypting: " + JSON.stringify(err));
        callback(err);
        return;
      }
      callback(null, true);
    });
	};

  exports.getPassword = function(key, callback) {
    var s = this.service();
    var storagePasswords = s.storagePasswords();

    storagePasswords.fetch(function(err, passwords) {
      if (err) {
        callback(err);
        return;
      }

      var outpass = "";

      passwords.list().forEach(function(pass) {
        if (pass._properties.username !== key) {
          return
        }

        outpass = pass._properties.clear_password;
      });

      callback(null, outpass);
    });
  };

  /**
   * This method actually retrieves audit events and inputs them into splunk.
   */
  exports.streamEvents = function(name, singleInput, eventWriter, done) {
    var pollingInterval = parseInt(singleInput.polling_interval, 10);
    var s = this.service();
    var self = this;

    async.auto({
      checkEncryption: function(callback) {
        if (singleInput.client_secret !== SECRET_MASK) {
          self.encrypt(singleInput.client_key, singleInput.client_secret, callback);
          return;
        }
        callback();
      },

      mask: ['checkEncryption', function(results, callback) {
        // No need to mask if we didn't encrypt
        if (!results.checkEncryption) {
          callback();
          return;
        }

        var endpoint = new splunkjs.Service.Endpoint(s, "data/inputs/"+INPUT_KIND+"/"+INPUT_NAME);

        endpoint.post("", {
          client_key: singleInput.client_key,
          client_secret: SECRET_MASK,
          team_name: singleInput.team_name,
          instance_address: singleInput.instance_address,
          polling_interval: singleInput.polling_interval
        }, function(err, val) {
          if (err) {
            Logger.info(INPUT_KIND, "input update error" + JSON.stringify(err));
            callback(err);
            return;
          }
          Logger.info(INPUT_KIND, "input update " + JSON.stringify(val));
          callback();
          return;
        });
      }],

      getPassword: ['mask', function(results, callback) {
        self.getPassword(singleInput.client_key, function(err, clearPass) {
          if (err) {
            Logger.info(INPUT_KIND, "error getting pass " + JSON.stringify(s));
            callback(err);
            return;
          }

          callback(null, clearPass);
        })
      }],

      run: ['getPassword', function(results, callback) {
        var sftInput = new ScaleftInput(
              singleInput.team_name,
              singleInput.instance_address,
              singleInput.client_key,
              results.getPassword
            );

        var checkpoint = sftInput.loadCheckpoint();

        if (checkpoint) {
          Logger.info(INPUT_KIND, "Loaded checkpoint data: " + checkpoint);
          sftInput.lastIndexOffset = checkpoint;
        }

        (function pollEvents() {
          Logger.info(INPUT_KIND, "Polling for new sft audit events.");

          async.auto({
            getEvents: sftInput.getEvents.bind(sftInput, eventWriter),
          }, function (err) {
            if (err) {
              Logger.error(INPUT_KIND, "Error while polling events. Sleeping for 1 polling period.");
            }
            setTimeout(pollEvents, pollingInterval * 1000);
          });
        })();
      }]

    }, function(err, results) {
      if (err) {
        Logger.error(INPUT_KIND, "Error while processing. " + err);
        return;
      }
    });
  };

  ModularInputs.execute(exports, module);
})();
