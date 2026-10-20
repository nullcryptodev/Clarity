// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>
#include <vector>

#include "Args.h"

namespace Bridge
{
  //  BridgeConfig
  //
  //  Loads a JSON config file into an Args struct. The file is a
  //  flat JSON object whose top-level keys mirror the CLI flag
  //  names, with per-chain config in a "chains" array. Missing
  //  keys are ignored; the caller's defaults survive.
  //
  //  Precedence (highest wins):
  //
  //    1. CLI flags
  //    2. Config file values
  //    3. Compiled-in defaults
  //
  //  The caller loads the config file into a fresh Args struct,
  //  then calls parseArgs which layers the CLI flags on top.
  //  parseArgs uses "empty string means unset" for the string
  //  fields, so a CLI flag that the operator did not pass leaves
  //  the config-loaded value intact.
  //
  //  Errors are reported via std::runtime_error with a message
  //  that names the file and the offending field, e.g.:
  //
  //    "watcher1.json: field 'clarity_rpc': expected 'host:port'"
  //
  //  This module is deliberately independent of Args::parseArgs
  //  (which is the CLI parser). It loads the file into Args, and
  //  the CLI parser calls it as its first step when --config-file
  //  is given.
  namespace BridgeConfig
  {
    //  Load the JSON config file at `path` into `args`. Does not
    //  clear `args` first — the caller is expected to pass a
    //  default-constructed Args (or one whose fields have already
    //  been pre-populated with defaults).
    //
    //  Returns true on success. Throws std::runtime_error with a
    //  descriptive message on failure (file not found, malformed
    //  JSON, unknown field type, invalid value).
    //
    //  Unknown fields are ignored with a warning to stderr. This
    //  is the right behavior for forward-compatibility: an old
    //  bridge app reading a config written for a newer one should
    //  not refuse to start, but the operator should see that
    //  something was ignored.
    bool load(const std::string &path, Args &args);
  } // namespace BridgeConfig

} // namespace Bridge