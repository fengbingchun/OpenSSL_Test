#include "funset.hpp"
#include <iostream>
#include <memory>
#include <string>
#include <grpcpp/grpcpp.h>
#include "helloworld.grpc.pb.h"

// Blog: https://blog.csdn.net/fengbingchun/article/details/100626030

// reference: grpc/examples/cpp/helloworld
namespace {

class GreeterClient {
public:
	GreeterClient(std::shared_ptr<grpc::Channel> channel) : stub_(helloworld::Greeter::NewStub(channel)) {}

	// Assembles the client's payload, sends it and presents the response back from the server.
  	std::string SayHello(const std::string& user) {
    		// Data we are sending to the server.
    		helloworld::HelloRequest request;
    		request.set_name(user);

    		// Container for the data we expect from the server.
    		helloworld::HelloReply reply;

    		// Context for the client. It could be used to convey extra information to the server and/or tweak certain RPC behaviors.
    		grpc::ClientContext context;

    		// The actual RPC.
    		grpc::Status status = stub_->SayHello(&context, request, &reply);

    		// Act upon its status.
    		if (status.ok()) {
      			return reply.message();
    		} else {
      			fprintf(stderr, "error code: %d, error message: %s\n", status.error_code(), status.error_message().c_str());
      			return "RPC failed";
   		}	
  	}	

private:
  	std::unique_ptr<helloworld::Greeter::Stub> stub_;
};

} // namespace

int test_grpc_client()
{
	fprintf(stdout, "client start\n");
  	// Instantiate the client. It requires a channel, out of which the actual RPCs are created.
	// This channel models a connection to an endpoint (in this case, localhost at port 50051).
	// We indicate that the channel isn't authenticated(use of InsecureChannelCredentials()).
  	GreeterClient greeter(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials()));
  	std::string user("world");
  	std::string reply = greeter.SayHello(user);
  	fprintf(stdout, "Greeter received: %s\n", reply.c_str());

	return 0;
}

namespace {

// Logic and data behind the server's behavior.
class GreeterServiceImpl final : public helloworld::Greeter::Service {
  	grpc::Status SayHello(grpc::ServerContext* context, const helloworld::HelloRequest* request, helloworld::HelloReply* reply) override {
    		std::string prefix("Hello ");
    		reply->set_message(prefix + request->name());
    		return grpc::Status::OK;
  	}
};

void RunServer() {
  	std::string server_address("0.0.0.0:50051");
  	GreeterServiceImpl service;

  	grpc::ServerBuilder builder;
  	// Listen on the given address without any authentication mechanism.
  	builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  	// Register "service" as the instance through which we'll communicate with clients.
	// In this case it corresponds to an *synchronous* service.
  	builder.RegisterService(&service);
  	// Finally assemble the server.
  	std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
  	fprintf(stdout, "Server listening on: %s\n", server_address.c_str());

  	// Wait for the server to shutdown. Note that some other thread must be
  	// responsible for shutting down the server for this call to ever return.
  	server->Wait();
}

} // namespace

int test_grpc_server()
{
	fprintf(stdout, "server start\n");
	RunServer();

	return 0;
}


