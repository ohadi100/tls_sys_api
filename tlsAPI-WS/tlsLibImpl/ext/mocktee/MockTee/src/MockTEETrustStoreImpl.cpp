/**
 *
 * \copyright
 * (c) 2022, 2023 CARIAD SE, All rights reserved.
 *
 * NOTICE:
 *
 * All the information and materials contained herein, including the
 * intellectual and technical concepts, are the property of CARIAD SE and may
 * be covered by patents, patents in process, and are protected by trade
 * secret and/or copyright law.
 *
 * The copyright notice above does not evidence any actual or intended
 * publication or disclosure of this source code, which includes information
 * and materials that are confidential and/or proprietary and trade secrets of
 * CARIAD SE.
 *
 * Any reproduction, dissemination, modification, distribution, public
 * performance, public display of or any other use of this source code and/or
 * any other information and/or material contained herein without the prior
 * written consent of CARIAD SE is strictly prohibited and in violation of
 * applicable laws.
 *
 * The receipt or possession of this source code and/or related information
 * does not convey or imply any rights to reproduce, disclose or distribute
 * its contents or to manufacture, use or sell anything that it may describe
 * in whole or in part.
 */


#include "MockTEETrustStoreImpl.h"

#include <iostream>
#include <fstream>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>

#include "TEEIds.h"

using vwg::tee::impl::MockTEETrustStoreImpl;
using namespace vwg::tee;
using namespace vwg::tee::impl::teeids;

int rmdirRecursive(const std::string &path);

// helper function to simplify directory deletion
int rmdirRecursive(const std::string &path)
{
    DIR* pDir;
    struct dirent* pDirEntry;

    /* directory does not exist, not an error per se */
    if (!(pDir = opendir(path.c_str())))
    {
        return 0;
    }

    while ((pDirEntry = readdir(pDir)) != nullptr)
    {
        std::string absPath;

        /* do not traverse up the directory tree, ignore "." and ".." */
        if (!strcmp(pDirEntry->d_name, ".") || !strcmp(pDirEntry->d_name, ".."))
        {
            continue;
        }

        /* create absolute path of file/directory */
        absPath = path;
        if (path.back() != '/')
        {
            absPath += '/';
        }
        absPath += pDirEntry->d_name;


        /* delete file or traverse down into directory */
        // TODO: Fix for QNX
        // if ((pDirEntry->d_type & DT_DIR) == DT_DIR && !((pDirEntry->d_type & DT_LNK) == DT_LNK))
        // {
        //     rmdirRecursive(absPath);
        // }
        // else
        // {
        //     unlink(absPath.c_str());
        // }
    }

    closedir(pDir);
    rmdir(path.c_str());

    return 0;
}


MockTEETrustStoreImpl::MockTEETrustStoreImpl()
{

}


MockTEETrustStoreImpl::~MockTEETrustStoreImpl()
{

}


CertificateBundle MockTEETrustStoreImpl::get_root_cert_bundle(TrustStoreID trustStoreId)
{
	std::lock_guard<std::mutex> fileLockGuard(m_fileLockMutex);
	CertificateBundle certBundle;

	std::ifstream ts_file(MOCKTEE_TRUSTSTORE_FOLDER+trustStoreId+TRUSTSTORE_POSTFIX);
	if (ts_file.is_open())
	{
		// load certificate data from file, return file contents without processing
		std::string data((std::istreambuf_iterator<char>(ts_file)), std::istreambuf_iterator<char>());
		certBundle = data;
	}

	return certBundle;
}


Error MockTEETrustStoreImpl::set_root_cert_bundle(TrustStoreID trustStoreId, CertificateBundle certBundle)
{
	std::lock_guard<std::mutex> fileLockGuard(m_fileLockMutex);
	if (certBundle.empty())
	{
		return MockTeeError::INVALID_PARAMETER;
	}

	// write certificate bundle to file without prior processing
	std::ofstream ts_file(MOCKTEE_TRUSTSTORE_FOLDER+trustStoreId+TRUSTSTORE_POSTFIX);
	if (!ts_file.is_open())
	{
		return MockTeeError::FILE_NOT_FOUND;
	}

	ts_file << certBundle;
	ts_file.close();

	return MockTeeError::OK;
}

Error MockTEETrustStoreImpl::remove_all_truststores()
{
	std::lock_guard<std::mutex> fileLockGuard(m_fileLockMutex);
	std::error_code errorCode;

	if (rmdirRecursive(MOCKTEE_TRUSTSTORE_FOLDER) != 0)
    {
	    std::cout << "Error removing TrustStore folder";
	}

    mkdir(MOCKTEE_TRUSTSTORE_FOLDER.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

	return MockTeeError::OK;
}
