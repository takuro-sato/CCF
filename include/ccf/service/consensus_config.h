// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/unit_strings.h"
#include "ccf/service/consensus_type.h"

namespace consensus
{
  struct Configuration
  {
    ConsensusType type = ConsensusType::CFT;
    ds::TimeString message_timeout = {"1000ms"};
    ds::TimeString election_timeout = {"5000ms"};

    bool operator==(const Configuration&) const = default;
    bool operator!=(const Configuration&) const = default;
  };
}
