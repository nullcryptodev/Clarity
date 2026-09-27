#include "Fixtures.h"

namespace Tests
{
  std::unique_ptr<Node::Node> RPC_MethodTestFixture::s_node;
  std::unique_ptr<Rpc::JsonRpcDispatcher> RPC_MethodTestFixture::s_dispatcher;
  NoopLogger RPC_MethodTestFixture::s_logger;
  std::filesystem::path RPC_MethodTestFixture::s_data_dir;
}