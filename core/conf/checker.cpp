/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014,  Regents of the University of California
 *
 * This file is part of NSL (NDN Signature Logger).
 * See AUTHORS.md for complete list of NSL authors and contributors.
 *
 * NSL is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NSL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NSL, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of nsl authors and contributors.
 */

#include "checker.hpp"

#include <boost/algorithm/string.hpp>

namespace nsl {
namespace conf {

Checker::~Checker()
{
}

CustomizedChecker::CustomizedChecker(uint32_t sigType,
                                     shared_ptr<KeyLocatorChecker> keyLocatorChecker)
  : m_sigType(sigType)
  , m_keyLocatorChecker(keyLocatorChecker)
{
  switch (sigType) {
  case tlv::SignatureSha256WithRsa:
  case tlv::SignatureSha256WithEcdsa:
    {
      if (!static_cast<bool>(m_keyLocatorChecker))
        throw Error("Strong signature requires KeyLocatorChecker");

      return;
    }
  case tlv::DigestSha256:
    return;
  default:
    throw Error("Unsupported signature type");
  }
}

bool
CustomizedChecker::check(const Data& data)
{
  const Signature signature = data.getSignature();
  if (m_sigType != signature.getType())
    return false;

  if (signature.getType() == tlv::DigestSha256)
    return true;

  try {
    switch (signature.getType()) {
    case tlv::SignatureSha256WithRsa:
    case tlv::SignatureSha256WithEcdsa:
      {
        if (!signature.hasKeyLocator())
          return false;
        break;
      }
    default:
      return false;
    }
  }
  catch (KeyLocator::Error&) {
    return false;
  }
  catch (tlv::Error& e) {
    return false;
  }

  std::string failInfo;
  return m_keyLocatorChecker->check(data, signature.getKeyLocator(), failInfo);
}

HierarchicalChecker::HierarchicalChecker(uint32_t sigType)
  : CustomizedChecker(sigType,
      make_shared<HyperKeyLocatorNameChecker>("^(<>*)$", "\\1",
                                              "^([^<KEY>]*)<KEY>(<>*)<ksk-.*><ID-CERT>$",
                                              "\\1\\2",
                                              KeyLocatorChecker::RELATION_IS_PREFIX_OF))
{
}

shared_ptr<Checker>
CheckerFactory::create(const ConfigSection& configSection)
{
  ConfigSection::const_iterator propertyIt = configSection.begin();

  // Get checker.type
  if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "type"))
    throw Error("Expect <checker.type>");

  std::string type = propertyIt->second.data();

  if (boost::iequals(type, "customized"))
    return createCustomizedChecker(configSection);
  else if (boost::iequals(type, "hierarchical"))
    return createHierarchicalChecker(configSection);
  else
    throw Error("Unsupported checker type: " + type);
}

shared_ptr<Checker>
CheckerFactory::createCustomizedChecker(const ConfigSection& configSection)
{
  ConfigSection::const_iterator propertyIt = configSection.begin();
  propertyIt++;

  // Get checker.sig-type
  if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "sig-type"))
    throw Error("Expect <checker.sig-type>");

  std::string sigType = propertyIt->second.data();
  propertyIt++;

  // Get checker.key-locator
  if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "key-locator"))
    throw Error("Expect <checker.key-locator>");

  shared_ptr<KeyLocatorChecker> keyLocatorChecker =
    KeyLocatorCheckerFactory::create(propertyIt->second);
  propertyIt++;

  if (propertyIt != configSection.end())
    throw Error("Expect the end of checker");

  return make_shared<CustomizedChecker>(getSigType(sigType), keyLocatorChecker);
}

shared_ptr<Checker>
CheckerFactory::createHierarchicalChecker(const ConfigSection& configSection)
{
  ConfigSection::const_iterator propertyIt = configSection.begin();
  propertyIt++;

  // Get checker.sig-type
  if (propertyIt == configSection.end() || !boost::iequals(propertyIt->first, "sig-type"))
    throw Error("Expect <checker.sig-type>");

  std::string sigType = propertyIt->second.data();
  propertyIt++;

  if (propertyIt != configSection.end())
    throw Error("Expect the end of checker");

  return make_shared<HierarchicalChecker>(getSigType(sigType));
}

uint32_t
CheckerFactory::getSigType(const std::string& sigType)
{
  if (boost::iequals(sigType, "rsa-sha256"))
    return tlv::SignatureSha256WithRsa;
  else if (boost::iequals(sigType, "ecdsa-sha256"))
    return tlv::SignatureSha256WithEcdsa;
  else if (boost::iequals(sigType, "sha256"))
    return tlv::DigestSha256;
  else
    throw Error("Unsupported signature type");
}

} // namespace conf
} // namespace nsl
